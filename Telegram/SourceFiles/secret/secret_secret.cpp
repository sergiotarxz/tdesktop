/**
 * Copyright: Sergio Iglesias (2022-2024)
 * License: https://github.com/sergiotarxz/tdesktop/blob/master/LEGAL
 */
#include "secret/secret_secret.h"
#include "mtproto/mtproto_dh_utils.h"
#include "mtproto/mtproto_auth_key.h"
#include "base/openssl_help.h"
#include "apiwrap.h"
#include "data/data_encrypted_chat.h"
#include "data/data_session.h"
#include "data/data_encrypted_chat.h"
#include "main/main_session.h"
#include "history/history.h"
#include <iostream>
#include <limits.h>
#include "window/window_session_controller.h"
#include "data/data_histories.h"
#include "history/history_item.h"
#include "base/unixtime.h"
#include "history/history_item_helpers.h" // NewMessageFlags.
#include "data/data_types.h"
#include "data/data_changes.h"
#include "history/history_unread_things.h"

namespace Secret {

class Secret;


const size_t byteCount = 256;
Secret::Secret(not_null<PeerData*> peer, bool isAuthor, Fn<void(gsl::not_null<PeerData*> gotPeer)> callback) :
                peer(peer),
		callback(callback),
                _finalKey(byteCount),
		_finalKeyFingerPrint(0),
		_isAuthor(isAuthor),
		_outNMessages(0),
		_inNMessages(0),
		_privateKey(byteCount),
		_ga(0),
		_publicKey(0),
                session(&(peer->session())) {
        printf("isAuthor: %d\n", (int)_isAuthor);
	printf("Survives entering constructor\n");
	populatePrivateKey();	
	populatePublicKey();
	printf("%s\n", "Built secret");
}

Secret::Secret(not_null<Main::Session *>session, bool isAuthor, Fn<void(gsl::not_null<PeerData*> gotPeer)> callback) :
		callback(callback),
                _finalKey(byteCount),
		_finalKeyFingerPrint(0),
		_isAuthor(isAuthor),
		_outNMessages(0),
		_inNMessages(0),
		_privateKey(byteCount),
		_ga(0),
		_publicKey(0),
                session(session) {
        peer = NULL;
        printf("isAuthor: %d\n", (int)_isAuthor);
	printf("Survives entering constructor\n");
	populatePrivateKey();	
	populatePublicKey();
	printf("%s\n", "Built secret");
}
void Secret::setPeer(not_null<PeerData *> peer) {
    this->peer = peer;
}

int Secret::idSecretChat = 1000;

void
Secret::calculateGA(const openssl::BigNum &vg) {
	openssl::BigNum privateKeyBigInt(_privateKey);
	_ga = openssl::BigNum::ModExp(
		vg,
		privateKeyBigInt,
		_prime);
}

void
Secret::calculateFinalKey(const bytes::vector &ga) {
	openssl::BigNum gaBigNum(ga);
	openssl::BigNum privateKeyBigInt(_privateKey);
	_finalKey = openssl::BigNum::ModExp(
		gaBigNum,
		privateKeyBigInt,
		_prime).getBytes();
	populateFinalKeyFingerprint();
	printf("Populated private final key with fingerprint:");
	bytes::vector keyHash = calcAuthKeyHash();
	for (std::byte &c : keyHash) {
		printf("%02X", (unsigned char) c);
	}
	printf("\n");
}

bytes::vector
Secret::calcAuthKeyHash(void) {
	bytes::vector sha1 = openssl::Sha1(_finalKey);
	bytes::vector result(16);
	std::copy_n(std::begin(sha1), 16, std::begin(result));
	return result;
}
void
Secret::acceptEncryption(void) {
	if (_ga.isZero())  {
		printf("No g_a still.\n");
		return;
	}
	if (_finalKeyFingerPrint == 0) {
		printf("No public key still.\n");
		return;
	}
	if (openssl::BigNum(_finalKey).isZero()) {
		printf("Private key is zero.\n");
		return;	
	}
	gsl::not_null<EncryptedChatData *>encryptedPeer(dynamic_cast<EncryptedChatData *>(&*peer));
	if (!encryptedPeer) {
		printf("Unable to cast peer to EncryptedChatData.\n");
		return;
	}
	if (encryptedPeer->inputEncrypted == NULL) {
		printf("%s\n", "This is not a valid peer to accept encryption");
		return;
	}
	const auto &input = *encryptedPeer->inputEncrypted;
	printf("Got input.\n");
	auto ga = _ga.getBytes();
	printf("Got ga.\n");
	peer->session().api().request(
		MTPmessages_AcceptEncryption(
				input,
				MTP_bytes(ga),
				MTP_long(_finalKeyFingerPrint)
		)
	).done([this] {
		printf("%s\n", "Accepted encrypted chat request.");
	}).fail([&] (const MTP::Error &error) {
		fprintf(stderr, "%s\n", (char *)error.type().toStdString().c_str());
	}).send();
}

void Secret::addToChatHistory(void) {
    auto encrypted = peer->asEncrypted();
    encrypted->setEncryptedChatTitle(realUser->name() + QString("🔏"));
    encrypted->setUserPicFromUser(realUser->asUser());
    auto history = encrypted->session().data().history(encrypted);
    encrypted->session().data().chatsList()->addEntry(history);
    auto folder  = encrypted->session().data().folder(1);
 
    history->setFolder(folder);
    encrypted->session().data().histories().requestDialogEntry(history);
    encrypted->session().data().refreshChatListEntry(history);
    encrypted->session().data().sendHistoryChangeNotifications();
    history->session().api().toggleHistoryArchived( history, false, [this, history, encrypted]() {
        addNewMessageSecretChatStarted();
        encrypted->session().changes().historyUpdated(history, Data::HistoryUpdate::Flag::UnreadMentions | Data::HistoryUpdate::Flag::UnreadView);
    });
}

void
Secret::sendEncryptedRequest(void) {
	if (realUser->input.type() != mtpc_inputPeerUser) {
		printf("%s\n", "This is not a valid peer to send and encrypted request.");
		return;
	}
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
	const auto &input = realUser->input.c_inputPeerUser();
	realUser->session().api().request(
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

void
Secret::getDiffieHellman(Fn<void()> done) {
	session->api().request(
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
			_prime = prime;
			calculateGA(openssl::BigNum(data.vg().v));
			printf("%s\n", "calculated _ga");
			done();
		}, [&](const MTPDmessages_dhConfigNotModified &data) {
			printf("not modified\n");
		});
	}).send();
}

bool
Secret::isAuthor(void) {
	return _isAuthor;
}

void
Secret::populatePublicKey(void) {
	_publicKey = generateKeyId(_privateKey);
	printf("%s\n", "Populated public key.");
}

void
Secret::populateFinalKeyFingerprint(void) {
	_finalKeyFingerPrint = generateKeyId(_finalKey);
	printf("%s\n", "Populated public final key.");
}

uint64
Secret::generateKeyId(const bytes::vector &key) {
	std::array<std::byte, 256> randomVectorArray;
	std::copy_n(key.begin(), 256, randomVectorArray.begin());
	MTP::AuthKey authKey(randomVectorArray);
	return authKey.keyId();
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

void
Secret::sendMessage(MTPdecryptedMessageLayer &decryptedMessageLayer) {
	std::random_device rd;
	std::uniform_int_distribution<unsigned char> char_generator(0, 255);
	mtpBuffer serializedMessageLayer;
	printf("Write serializedMessageLayer.\n");
	decryptedMessageLayer.write(serializedMessageLayer);
	bytes::vector plaintext;
	for (uint32 u : serializedMessageLayer) {
		for (size_t i = 0; i<4; i++) {
			size_t currentShift = i;
			std::byte a = (std::byte) (u >> (8 * currentShift));
			plaintext.insert(plaintext.end(), a);
		}
	}
	for (size_t i = 0; i<4; i++) {
		size_t currentShift = 3-i;
		std::byte a = (std::byte) (decryptedMessageLayer.type() >> (8 * currentShift));
		plaintext.insert(plaintext.begin(), a);
	}
	uint32 plaintext_len(plaintext.size());
	for (size_t i = 0; i<4; i++) {
		size_t currentShift = 3-i;
		std::byte a = (std::byte) (plaintext_len >> (8 * currentShift));
		plaintext.insert(plaintext.begin(), a);
	}
	int pad_to_min = 1024 - 16;
	for (size_t i = 0; i < pad_to_min || plaintext.size() % 16 != 0; i++) {
		plaintext.insert(plaintext.end(), (std::byte) char_generator(rd));
	}
	auto x = isAuthor() ? 0 : 8;
	auto &finalKey = _finalKey;

	auto finalKeyPrepend = bytes::vector(&finalKey[88], &finalKey[88+32]);

	bytes::vector toSha(finalKeyPrepend.begin(), finalKeyPrepend.end());
	toSha.insert(toSha.end(), plaintext.begin(), plaintext.end());

	auto msgKeyLarge = openssl::Sha256(toSha);
	bytes::vector msgKey(&msgKeyLarge[8], &msgKeyLarge[8+16]);
	
	auto sha256A = calcShaA(x, finalKey, msgKey);
	auto sha256B = calcShaB(x, finalKey, msgKey);
	auto aesKey  = calcAesKey(sha256A, sha256B);
	auto aesIv   = calcAesIv(sha256A, sha256B);

	bytes::vector encryptedPayload(plaintext.size());
	MTP::aesIgeEncryptRaw(plaintext.data(), encryptedPayload.data(), plaintext.size(), aesKey.data(), aesIv.data());

	encryptedPayload.insert(encryptedPayload.begin(), msgKey.begin(), msgKey.end());

	for (size_t i = 0; i<8; i++) {
		size_t currentShift = 7 - i;
		std::byte a = (std::byte) (_finalKeyFingerPrint >> (8 * currentShift));
		encryptedPayload.insert(encryptedPayload.begin(), a);
	}

	MTPlong randomId = MTP_long(0);	
	auto &decryptedLayer17 = decryptedMessageLayer.c_endtoend_17_decryptedMessageLayer();
	if (auto decryptedMessage = &decryptedLayer17.vmessage().c_endtoend_73_decryptedMessage()) {
		randomId = decryptedMessage->vrandom_id();
	} else if (auto decryptedMessage =
			&decryptedLayer17.vmessage().c_endtoend_45_decryptedMessage()) {
		randomId = decryptedMessage->vrandom_id();
	} else if (auto decryptedMessage =
			&decryptedLayer17.vmessage().c_endtoend_17_decryptedMessage()) {
		randomId = decryptedMessage->vrandom_id();
	} else if (auto decryptedMessage =
			&decryptedLayer17.vmessage().c_endtoend_17_decryptedMessageService()) {
		randomId = decryptedMessage->vrandom_id();
	} else if (auto decryptedMessage =
			&decryptedLayer17.vmessage().c_endtoend_8_decryptedMessage()) {
		randomId = decryptedMessage->vrandom_id();
	} else if (auto decryptedMessage =
			&decryptedLayer17.vmessage().c_endtoend_8_decryptedMessageService()) {
		randomId = decryptedMessage->vrandom_id();
	}
	peer->session().api().request(MTPmessages_SendEncrypted(
			MTP_flags(0),
			*peer->asEncrypted()->inputEncrypted,
			randomId,
			MTP_bytes(encryptedPayload)
		)
	).done([&] {
                printf("%ld %ld\n", _outNMessages, _inNMessages);
                _outNMessages++;
		printf("Success sending secret message\n");
	}).fail([&] {
		printf("Fail sending secret message\n");
	}).send();
}

void
insertSecret(Main::Session &session, Secret *secret) {
        auto encryptedPeer = secret->peer;
        printf("New secret: %lld\n", encryptedPeer->id.value);
	session.data().secretHash[encryptedPeer->id.value] = secret;
}

void
insertPendingSecret(Main::Session &session, Secret *secret) {
	session.data().secretHashPendingInvitations[secret->realUser->id.value] = secret;
}

void
handleUpdateEncryption(Main::Session &session, const MTPupdate &update, Fn<void(gsl::not_null<PeerData*>)> callback) {
	auto &encryptedChat = update.c_updateEncryption().vchat();
	if (encryptedChat.type() == mtpc_encryptedChatRequested) {
		handleUpdateEncryptedChatRequested(session, encryptedChat.c_encryptedChatRequested(), callback);
	}
	if (encryptedChat.type() == mtpc_encryptedChat) {
		handleUpdateEncryptedChat(session, encryptedChat.c_encryptedChat());
	}
}

void
handleUpdateEncryptedChatRequested(Main::Session &session, const MTPDencryptedChatRequested &encryptedRequested, Fn<void(gsl::not_null<PeerData*>)> callback) {
        uint64 id = encryptedRequested.vid().v;
	auto access_hash = encryptedRequested.vaccess_hash().v;
	auto ga = bytes::make_vector(encryptedRequested.vg_a().v);
	MTPInputEncryptedChat peer = MTP_inputEncryptedChat(MTP_int(id), MTP_long(access_hash));
        auto newId = PeerId(EncryptedId(id));
	auto peerEncryptedData = session.data().peer(newId)->asEncrypted();
	peerEncryptedData->inputEncrypted = new MTPInputEncryptedChat(peer);
	auto secret = new Secret(peerEncryptedData, false, callback);
	auto otherPeerId = encryptedRequested.vadmin_id().v;
	auto otherUser = session.data().user(UserId(otherPeerId));
        secret->realUser = otherUser;

	printf("Survives secret creation.\n");

	secret->getDiffieHellman([secret, &session, ga, callback] {
		secret->calculateFinalKey(ga);
		secret->acceptEncryption();
		insertSecret(session, secret);
                callback(secret->peer);
	});
}

void Secret::incrementInputMessages() {
    _inNMessages++;
}

void handleUpdateNewEncryptedMessage(Main::Session &session,
		const MTPDupdateNewEncryptedMessage &updateNewEncryptedMessage) {
    auto &message = updateNewEncryptedMessage.vmessage();
    if (message.type() == mtpc_encryptedMessageService) {
        printf("Reachs mtpc_updateNewEncryptedMessageService.\n");
        auto encryptedMessage = &message.c_encryptedMessageService();
        auto &chatId = encryptedMessage->vchat_id().v;
        auto secret = session.data().secretHash[chatId];
        printf("isAuthor: %d\n", secret->isAuthor());
        secret->incrementInputMessages();
        return;
    }
    if (message.type() == mtpc_encryptedMessage) {
        printf("Reachs mtpc_updateNewEncryptedMessage.\n");
        auto encryptedMessage = &message.c_encryptedMessage();
        auto &chatId = encryptedMessage->vchat_id().v;
        auto secret = session.data().secretHash[chatId];
        printf("isAuthor: %d\n", secret->isAuthor());
        secret->incrementInputMessages();
        auto x = secret->isAuthor() ? 8 : 0;
        auto &finalKey = secret->_finalKey;
        auto bytes = bytes::make_vector(encryptedMessage->vbytes().v);
        bytes::vector receivedMessageFinalKeyFingerprintVector(bytes.begin(), bytes.begin() + 8);
        uint64 receivedMessageFinalKeyFingerprint = 0;
        for (size_t i = 0; i < 8; i++) {
                size_t shift = i;
                receivedMessageFinalKeyFingerprint |=
                                (uint64) receivedMessageFinalKeyFingerprintVector[i] << shift * 8;
        }

        if (receivedMessageFinalKeyFingerprint != secret->_finalKeyFingerPrint) {
                printf("%s\n", "Secret key doesn't match the received key.");
                return;
        }
        bytes::vector msgKey(bytes.begin() + 8, bytes.begin() + 8 + 16);
        bytes::vector encryptedPayload(bytes.begin() + 8 + 16, bytes.end());
        auto sha256A = calcShaA(x, finalKey, msgKey);
        auto sha256B = calcShaB(x, finalKey, msgKey);
        auto aesKey  = calcAesKey(sha256A, sha256B);
        auto aesIv   = calcAesIv(sha256A, sha256B);
        bytes::vector plaintext(encryptedPayload.size());
        MTP::aesIgeDecryptRaw(encryptedPayload.data(), plaintext.data(),
                        encryptedPayload.size(), aesKey.data(), aesIv.data());
        bytes::vector sizeVector(plaintext.begin(), plaintext.begin() + 4);
        uint32 size = 0;
        for (size_t i = 0; i < 4; i++) {
                size_t shift = i;
                size |= (uint32) sizeVector[i] << (8 * shift);
        }

        bytes::vector objectTypeVector(plaintext.begin() + 4, plaintext.begin() + 8);
        uint32 objectType = 0;
        for (size_t i = 0; i < 4; i++) {
                size_t shift = i;
                objectType |= (uint32) objectTypeVector[i] << (8 * shift);
        }
        if (objectType != mtpc_endtoend_17_decryptedMessageLayer) {
                printf("Unsupported encrypted object received\n");
                return;
        }
        bytes::vector objectByteVector(plaintext.begin() + 8, plaintext.begin() + 8 + size);
        std::vector<mtpPrime> objectUint32Vector;
        mtpPrime currentUint32 = 0;
        bool isProcessing = false;
        bool firstIteration = true;
        for (size_t i = 0; i < objectByteVector.size(); i++) {
                if (i % 4 == 0 && !firstIteration) {
                        objectUint32Vector.insert(objectUint32Vector.end(), currentUint32);
                        currentUint32 = 0;
                        isProcessing = false;
                } else {
                        isProcessing = true;
                }
                size_t shift = i % 4;
                currentUint32 |= (uint32) objectByteVector[i] << (8 * shift);
                firstIteration = false;
        }
        if (isProcessing) {
                objectUint32Vector.insert(objectUint32Vector.end(), currentUint32);
        }
        MTPdecryptedMessageLayer decryptedMessageLayer;
        const mtpPrime *start = objectUint32Vector.data();
        if (decryptedMessageLayer.read(start,
                        start+objectUint32Vector.size()-1)) {
            if (auto decryptedMessageLayer17
                            = &decryptedMessageLayer.c_endtoend_17_decryptedMessageLayer()) {
                auto &message = decryptedMessageLayer17->vmessage();
                QString text("");
                if (auto decryptedMessage = &message.c_endtoend_73_decryptedMessage()) {
                        text = decryptedMessage->vmessage().v;
                } else if (auto decryptedMessage = &message.c_endtoend_45_decryptedMessage()) {
                        text = decryptedMessage->vmessage().v;
                } else if (auto decryptedMessage = &message.c_endtoend_17_decryptedMessage()) {
                        text = decryptedMessage->vmessage().v;
                } else if (auto decryptedMessage = &message.c_endtoend_8_decryptedMessage()) {
                        text = decryptedMessage->vmessage().v;
                } else if (auto decryptedMessage = &message.c_endtoend_8_decryptedMessage()) {
                        text = decryptedMessage->vmessage().v;
                }
                auto encrypted = secret->peer->asEncrypted();
                auto history = encrypted->session().data().history(encrypted);
                auto result = TextWithEntities{ text };
                auto emptyValue = QString("");
                if (result.text.isEmpty()) {
                    result.text = emptyValue;
                    if (!emptyValue.isEmpty()) {
                        result.entities.push_back({
                            EntityType::Italic,
                            0,
                            int(emptyValue.size()) 
                        });
                    }
                } else {
                    TextUtilities::ParseEntities(
                        result,
                        TextParseLinks
                        | TextParseMentions
                        | TextParseHashtags
                    );
                }
                auto historyItem = history->addNewLocalMessage(                    {
                        .id = history->nextNonHistoryEntryId(),
                        .flags = MessageFlag::HasFromId | MessageFlag::HasPostAuthor | MessageFlag::ClientSideUnread,
                        .from = secret->realUser->id,
                        .date = base::unixtime::now()
                    }, std::move(result), MTP_messageMediaEmpty()
                );
                historyItem->addToUnreadThings(HistoryUnreadThings::AddType::New);
                history->setUnreadCount(history->unreadCount() + 1);
                encrypted->session().changes().historyUpdated(history, Data::HistoryUpdate::Flag::UnreadMentions | Data::HistoryUpdate::Flag::UnreadView);
                encrypted->session().data().histories().requestDialogEntry(history);
                encrypted->session().data().histories().sendPendingReadInbox(history);
                encrypted->session().data().refreshChatListEntry(history);
                encrypted->session().data().sendHistoryChangeNotifications();
            }
        }
    }
}

void Secret::addNewMessageSecretChatStarted() {
    auto history = peer->session().data().history(&*peer);
    auto text = QString("Secret chat with ") + realUser->name() + QString(" started");
    auto result = TextWithEntities{ text };

    auto emptyValue = QString("");
    if (result.text.isEmpty()) {
        result.text = emptyValue;
        if (!emptyValue.isEmpty()) {
            result.entities.push_back({
                EntityType::Italic,
                0,
                int(emptyValue.size()) 
            });
        }
    } else {
        TextUtilities::ParseEntities(
            result,
            TextParseLinks
            | TextParseMentions
            | TextParseHashtags
        );
    }
    history->addNewLocalMessage(                    {
            .id = history->nextNonHistoryEntryId(),
            .flags = 0,
            .date = base::unixtime::now()
        }, std::move(result), MTP_messageMediaEmpty()
    );
}

void 
handleUpdateEncryptedChat(Main::Session &session, const MTPDencryptedChat &encryptedChat) {
	printf("Reachs mtpc_encryptedChat\n");
	const auto window = session.windows().front();
	auto id = encryptedChat.vid().v;
	auto otherPeerId = encryptedChat.vparticipant_id().v;
	if (!session.data().secretHashPendingInvitations[otherPeerId]) {
		printf("%s\n", "Encryption not requested.");
		return;
	}
	auto &secret = session.data().secretHashPendingInvitations[otherPeerId];
	printf("%s\n", "Getting peer as encrypted.");
	auto encrypted = session.data().peer(EncryptedId(id))->asEncrypted();
	auto inputEncrypted = MTP_inputEncryptedChat(encryptedChat.vid(),
		encryptedChat.vaccess_hash());
	encrypted->inputEncrypted = new MTPInputEncryptedChat(inputEncrypted);
        secret->setPeer(encrypted);
        insertSecret(session, secret);
	printf("%s\n", "Calculating final key.");
	secret->calculateFinalKey(bytes::make_vector(encryptedChat.vg_a_or_b().v));
        printf("PEER_ID: %lld\n", otherPeerId);

	encrypted->setEncryptedChatTitle(secret->realUser->name() + QString("🔏"));
	encrypted->setUserPicFromUser(&*secret->realUser);
	auto history = encrypted->session().data().history(encrypted);
        encrypted->session().data().chatsList()->addEntry(history);
	auto folder  = encrypted->session().data().folder(1);
	history->setFolder(folder);
	encrypted->session().data().histories().requestDialogEntry(history);
	encrypted->session().data().refreshChatListEntry(history);
	encrypted->session().data().sendHistoryChangeNotifications();
	using Flag = MTPDendtoend_73_decryptedMessage::Flag;
        history->session().api().toggleHistoryArchived( history, false, [secret, history, encrypted]() {
            secret->addNewMessageSecretChatStarted();
            encrypted->session().changes().historyUpdated(history, Data::HistoryUpdate::Flag::UnreadMentions | Data::HistoryUpdate::Flag::UnreadView);
        });
	secret->callback(encrypted);
}

void Secret::sendMessage(QString text) {
	std::random_device rd;
	std::uniform_int_distribution<uint64> dist(0, LONG_MAX);
	uint64 randomId = dist(rd);
	std::uniform_int_distribution<unsigned char> char_generator(0, 255);
	auto decryptedMessage = MTP_endtoend_73_decryptedMessage(MTP_flags(0),
			MTP_long(randomId), MTP_int(3600),
			MTP_string(text), MTP_endtoend_8_decryptedMessageMediaEmpty(),
			MTP_vector<MTPMessageEntity>(), MTP_string(), MTPlong(), MTPlong());
	bytes::vector bytesRandom(15);
	std::generate(bytesRandom.begin(),
		bytesRandom.end(), [&] (void) mutable {
			std::byte b = (std::byte) char_generator(rd);
			return b;
	});
	auto decryptedMessageLayer = MTP_endtoend_17_decryptedMessageLayer(
			MTP_bytes(bytesRandom), MTP_int(73),
			MTP_int(_inNMessages*2 + (isAuthor() ? 0 : 1) ),
			MTP_int(_outNMessages*2 + (isAuthor() ? 1 : 0) ),
			decryptedMessage);
	sendMessage(decryptedMessageLayer);
}

bytes::vector
calcAesIv(bytes::vector &sha256A, bytes::vector &sha256B) {
	bytes::vector aesIv(&sha256B[0], &sha256B[8]);
	aesIv.insert(aesIv.end(), &sha256A[8], &sha256A[8+16]);
	aesIv.insert(aesIv.end(), sha256B.begin()+24, sha256B.end());
	return aesIv;
}

bytes::vector
calcAesKey(bytes::vector &sha256A, bytes::vector &sha256B) {
	bytes::vector aesKey(&sha256A[0], &sha256A[8]); 
	aesKey.insert(aesKey.end(), &sha256B[8], &sha256B[8+16]);
	aesKey.insert(aesKey.end(), sha256A.begin()+24, sha256A.end());
	return aesKey;
}

bytes::vector
calcShaB(int x, bytes::vector &finalKey, bytes::vector &msgKey) {
	bytes::vector toSha256B(&finalKey[40+x], &finalKey[40+x+36]);
	toSha256B.insert(toSha256B.end(), msgKey.begin(), msgKey.end());
	return openssl::Sha256(toSha256B);

}

bytes::vector
calcShaA(int x, bytes::vector &finalKey, bytes::vector &msgKey) {
	bytes::vector toSha256A(msgKey.begin(), msgKey.end());
	toSha256A.insert(toSha256A.end(), &finalKey[x], &finalKey[x+36]);
	return openssl::Sha256(toSha256A);
}
} // namespace Secret
