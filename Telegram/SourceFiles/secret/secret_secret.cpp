#include "secret/secret_secret.h"
#include "mtproto/mtproto_dh_utils.h"
#include "mtproto/mtproto_auth_key.h"
#include "base/openssl_help.h"
#include "apiwrap.h"
#include "main/main_session.h"
#include <iostream>
#include <limits.h>

namespace Secret {
Secret::Secret(PeerData *user) :
		_privateKey(_byteCount),
		_peer(user),
		_ga(0),
		_session(&user->session()),
		_publicKey(0) {
	populatePrivateKey();	
	populatePublicKey();
	printf("%s\n", "Built secret");
}

void
Secret::calculateGA(const openssl::BigNum &vg, const openssl::BigNum &prime) {
	openssl::BigNum privateKeyBigInt(_privateKey);
	_ga = openssl::BigNum::ModExp(
		vg,
		privateKeyBigInt,
		prime);
}

void
Secret::sendEncryptedRequest(void) {
	if (_ga.isZero())  {
		printf("No g_a still.\n");
		return;
	}
	if (_publicKey == 0) {
		printf("No public key still.\n");
		return;
	}
	if (openssl::BigNum(_privateKey).isZero()) {
		printf("Private key is zero.\n");
		return;	
	}
	if (_peer->input.type() == mtpc_inputPeerUser) {
		const auto &input = _peer->input.c_inputPeerUser();
		_session->api().request(
			MTPmessages_RequestEncryption(
				MTP_inputUser(MTP_long(input.vuser_id().v),
						MTP_long(input.vaccess_hash().v)),
				MTP_int(_publicKey),
				MTP_bytes(_ga.getBytes())
			)
		).done([&] {
			printf("%s\n", "Sent request.");
		}).fail([&] (const MTP::Error &error) {
			fprintf(stderr, "%s\n", (char *)error.type().toStdString().c_str());
		}).send();
	}
}

void
Secret::getDiffieHellman(Fn<void()> done) {
	_session->api().request(
		MTPmessages_GetDhConfig()
	).done([=](const MTPmessages_DhConfig &result) {
		result.match([&](const MTPDmessages_dhConfig &data) {
			using namespace openssl;
			auto primeBytes = bytes::make_vector(data.vp().v);
			if (!MTP::IsPrimeAndGood(primeBytes, data.vg().v)) {
				LOG(("API Error: bad p/g received in dhConfig."));
				return;
			}
			openssl::BigNum prime(primeBytes);
			calculateGA(openssl::BigNum(data.vg().v), prime);
			printf("%s\n", "calculated _ga");
			done();
		}, [&](const MTPDmessages_dhConfigNotModified &data) {
			printf("not modified\n");
		});
	}).send();
}

void
Secret::populatePublicKey(void) {
	std::array<std::byte, 256> randomVectorArray;
	std::copy_n(_privateKey.begin(), 256, randomVectorArray.begin());
	MTP::AuthKey authKey(randomVectorArray);
	_publicKey = authKey.keyId();
	printf("%s\n", "Populated public key.");
}

void
Secret::populatePrivateKey(void) {
	std::random_device rd;
	std::uniform_int_distribution<unsigned char> dist(0, 255);
	std::generate(std::begin(_privateKey),
		std::end(_privateKey), [&] (void) mutable {
			 std::byte b = (std::byte) dist(rd);
			 return b;
	});
	printf("%s\n", "Populated private key.");
}
} // namespace Secret
