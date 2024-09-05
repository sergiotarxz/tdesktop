/**
 * Copyright: Sergio Iglesias (2022)
 * License: https://github.com/sergiotarxz/tdesktop/blob/master/LEGAL
 **/
#pragma once

#include "data/data_peer.h"
#include "data/data_user.h"

enum class EncryptedChatDataFlag : uint32 {
    Empty = 0
};
using EncryptedChatDataFlags = base::flags<EncryptedChatDataFlag>;
class EncryptedChatData : public PeerData {
public:
	using Flag = EncryptedChatDataFlag;
	using Flags = Data::Flags<EncryptedChatDataFlags>;
        inline constexpr bool is_flag_type(EncryptedChatDataFlag) { return true; };
	EncryptedChatData(not_null<Data::Session*> owner, PeerId id);
	MTPInputEncryptedChat *inputEncrypted;
	void setEncryptedChatTitle(QString);
	bool canWrite() const {
		return true;
	}
	void setUserPicFromUser(UserData *user);
	auto flagsValue() const {
		return _flags.value();
	}
private:
	Flags _flags;
};
