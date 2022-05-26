#include "data/data_peer_values.h"
#include "data/data_user.h"
#include "data/data_peer.h"
#include "base/openssl_help.h"
#include "base/bytes.h"

namespace Secret {
class Secret {
public:
	Secret(PeerData *);
	void createSecretChat(void);
	void getDiffieHellman(Fn<void()>);
	void sendEncryptedRequest(void);
private:
	const size_t _byteCount = 256;
	void populatePrivateKey(void);
	void populatePublicKey(void);
	void calculateGA(const openssl::BigNum &,
			const openssl::BigNum &);
	bytes::vector _privateKey;
	PeerData *_peer;
	openssl::BigNum _ga;
	Main::Session *_session;
	int _publicKey;
};
} // namespace Secret
