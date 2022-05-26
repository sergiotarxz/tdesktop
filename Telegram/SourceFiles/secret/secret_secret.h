/**
 * Copyright: Sergio Iglesias (2022)
 * License: https://github.com/sergiotarxz/tdesktop/blob/master/LEGAL
 */
#ifndef SECRET_HEADER
#define SECRET_HEADER
#include "data/data_peer_values.h"
#include "data/data_user.h"
#include "data/data_peer.h"
#include "base/openssl_help.h"
#include "base/bytes.h"

namespace Secret {

class Secret;

void handleUpdateEncryption(Main::Session *session,
		const MTPupdate &update);
void handleUpdateEncryptedChatRequested(Main::Session *session,
		const MTPDencryptedChatRequested &encryptedRequested);
void handleUpdateEncryptedChat(Main::Session *session,
		const MTPDencryptedChat &encryptedChat);
void handleUpdateNewEncryptedMessage(Main::Session *session,
		const MTPDupdateNewEncryptedMessage &updateNewEncryptedMessage);
void insertSecret(Main::Session *session, Secret *secret);
void insertPendingSecret(Main::Session *session, Secret *secret);
bytes::vector calcAesIv(bytes::vector &sha256A, bytes::vector &sha256B);
bytes::vector calcAesKey(bytes::vector &sha256A, bytes::vector &sha256B);
bytes::vector calcShaB(int x, bytes::vector &finalKey, bytes::vector &msgKey);
bytes::vector calcShaA(int x, bytes::vector &finalKey, bytes::vector &msgKey);

class Secret {
public:
	Secret(PeerData *, bool isAuthor);
	void createSecretChat(void);
	void getDiffieHellman(Fn<void()>);
	void calculateFinalKey(const bytes::vector &);
	void sendEncryptedRequest(void);
	void acceptEncryption(void);
	bool isAuthor(void);
	void sendMessage(MTPdecryptedMessageLayer &decryptedMessageLayer);
	bytes::vector calcAuthKeyHash(void);
	PeerData *peer;
	bytes::vector _finalKey;
	uint64 _finalKeyFingerPrint;
	
private:
	long _isAuthor;
	long _outNMessages;
	bool _inNMessages;
	const size_t _byteCount = 256;
	void populatePrivateKey(void);
	void populatePublicKey(void);
	void populateFinalKeyFingerprint(void);
	uint64 generateKeyId(const bytes::vector &);
	void calculateGA(const openssl::BigNum &);
	bytes::vector _privateKey;
	openssl::BigNum _ga;
	openssl::BigNum _prime;
	int _publicKey;
};
} // namespace Secret
#endif
