#include <iostream>
#include "data/data_encrypted_chat.h"

EncryptedChatData::EncryptedChatData(not_null<Data::Session*> owner, PeerId id) :
    PeerData(owner, id),
    inputEncrypted(NULL),
    _flags(Flag(0)) {
}

void
EncryptedChatData::setEncryptedChatTitle(QString title) {
	//requestChatTitle(title);
        std::cout << title.toStdString() << std::endl;
	updateNameDelayed(title, QString(), QString());
}
void EncryptedChatData::setUserPicFromUser(UserData *user) {
	setUserpic(user->userpicPhotoId(), user->getUserpic()->location(), user->userpicHasVideo()); 
}
