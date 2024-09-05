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
#include "data/data_session.h"

namespace Secret {

class Secret;

void handleUpdateEncryption(Main::Session &session,
		const MTPupdate &update, Fn<void(gsl::not_null<PeerData*>)> callback);
void handleUpdateEncryptedChatRequested(Main::Session &session,
		const MTPDencryptedChatRequested &encryptedRequested, Fn<void(gsl::not_null<PeerData*> gotPeer)>);
void handleUpdateEncryptedChat(Main::Session &session,
		const MTPDencryptedChat &encryptedChat);
void handleUpdateNewEncryptedMessage(Main::Session &session,
		const MTPDupdateNewEncryptedMessage &updateNewEncryptedMessage);
void insertSecret(Main::Session &session, Secret *secret);
void insertPendingSecret(Main::Session &session, Secret *secret);
bytes::vector calcAesIv(bytes::vector &sha256A, bytes::vector &sha256B);
bytes::vector calcAesKey(bytes::vector &sha256A, bytes::vector &sha256B);
bytes::vector calcShaB(int x, bytes::vector &finalKey, bytes::vector &msgKey);
bytes::vector calcShaA(int x, bytes::vector &finalKey, bytes::vector &msgKey);

class Secret {
public:
	Secret(not_null<PeerData *>, bool isAuthor, Fn<void(gsl::not_null<PeerData*> peer)> callback);
        Secret(not_null<Main::Session *>session, bool isAuthor, Fn<void(gsl::not_null<PeerData*> gotPeer)> callback);
	void createSecretChat(void);
	void getDiffieHellman(Fn<void()>);
	void calculateFinalKey(const bytes::vector &);
	void sendEncryptedRequest(void);
	void acceptEncryption(void);
	bool isAuthor(void);
	void sendMessage(MTPdecryptedMessageLayer &decryptedMessageLayer);
	void sendMessage(QString text);
	bytes::vector calcAuthKeyHash(void);
	PeerData *peer;
        Fn<void(gsl::not_null<PeerData*> peer)> callback;
	bytes::vector _finalKey;
	uint64 _finalKeyFingerPrint;
        UserData *realUser;
        void addToChatHistory(void);
        void incrementInputMessages();
        void addNewMessageSecretChatStarted();
        void setPeer(not_null<PeerData *>);
private:
	long _isAuthor;
	long _outNMessages;
	long _inNMessages;
	void populatePrivateKey(void);
	void populatePublicKey(void);
	void populateFinalKeyFingerprint(void);
	uint64 generateKeyId(const bytes::vector &);
	void calculateGA(const openssl::BigNum &);
	bytes::vector _privateKey;
	openssl::BigNum _ga;
	openssl::BigNum _prime;
	int _publicKey;
        static int idSecretChat;
        not_null<Main::Session *>session;
};
} // namespace Secret
#endif
