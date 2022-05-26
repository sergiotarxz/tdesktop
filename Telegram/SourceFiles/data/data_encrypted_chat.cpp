#include "data/data_encrypted_chat.h"

EncryptedChatData::EncryptedChatData(not_null<Data::Session*> owner, PeerId id) :
		PeerData(owner, id),
		inputEncrypted(NULL) {
}

void
EncryptedChatData::setEncryptedChatTitle(QString title) {
	_requestChatTitle = title;
	updateNameDelayed(requestChatTitle(), QString(), QString());
}
void EncryptedChatData::setUserPicFromUser(UserData *user) {
	setUserpic(user->userpicPhotoId(), user->getUserpic()->location()); 
}
