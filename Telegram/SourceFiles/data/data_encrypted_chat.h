/**
 * Copyright: Sergio Iglesias (2022)
 * License: https://github.com/sergiotarxz/tdesktop/blob/master/LEGAL
 **/
#pragma once

#include "data/data_peer.h"
#include "data/data_user.h"

class EncryptedChatData : public PeerData {
public:
	EncryptedChatData(not_null<Data::Session*> owner, PeerId id);
	MTPInputEncryptedChat *inputEncrypted;
	void setEncryptedChatTitle(QString);
	bool canWrite() const {
		return true;
	}
	void setUserPicFromUser(UserData *user);
};
