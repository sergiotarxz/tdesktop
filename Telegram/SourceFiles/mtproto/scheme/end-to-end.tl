//===8===
endtoend.8.decryptedMessage#1f814f1f random_id:long random_bytes:bytes message:string media:DecryptedMessageMedia = DecryptedMessage;
endtoend.8.decryptedMessageService#aa48327d random_id:long random_bytes:bytes action:DecryptedMessageAction = DecryptedMessage;
endtoend.8.decryptedMessageMediaEmpty#89f5c4a = DecryptedMessageMedia;
endtoend.8.decryptedMessageMediaPhoto#32798a8c thumb:bytes thumb_w:int thumb_h:int w:int h:int size:int key:bytes iv:bytes = DecryptedMessageMedia;
endtoend.8.decryptedMessageMediaVideo#4cee6ef3 thumb:bytes thumb_w:int thumb_h:int duration:int w:int h:int size:int key:bytes iv:bytes = DecryptedMessageMedia;
endtoend.8.decryptedMessageMediaGeoPoint#35480a59 lat:double long:double = DecryptedMessageMedia;
endtoend.8.decryptedMessageMediaContact#588a0a97 phone_number:string first_name:string last_name:string user_id:int = DecryptedMessageMedia;
endtoend.8.decryptedMessageActionSetMessageTTL#a1733aec ttl_seconds:int = DecryptedMessageAction;
endtoend.8.decryptedMessageMediaDocument#b095434b thumb:bytes thumb_w:int thumb_h:int file_name:string mime_type:string size:int key:bytes iv:bytes = DecryptedMessageMedia;
endtoend.8.decryptedMessageMediaAudio#6080758f duration:int size:int key:bytes iv:bytes = DecryptedMessageMedia;
endtoend.8.decryptedMessageActionReadMessages#c4f40be random_ids:Vector<long> = DecryptedMessageAction;
endtoend.8.decryptedMessageActionDeleteMessages#65614304 random_ids:Vector<long> = DecryptedMessageAction;
endtoend.8.decryptedMessageActionScreenshotMessages#8ac1f475 random_ids:Vector<long> = DecryptedMessageAction;
endtoend.8.decryptedMessageActionFlushHistory#6719e45c = DecryptedMessageAction;

//===17===
endtoend.17.decryptedMessage#204d3878 random_id:long ttl:int message:string media:DecryptedMessageMedia = DecryptedMessage;
endtoend.17.decryptedMessageService#73164160 random_id:long action:DecryptedMessageAction = DecryptedMessage;
endtoend.17.decryptedMessageMediaVideo#524a415d thumb:bytes thumb_w:int thumb_h:int duration:int mime_type:string w:int h:int size:int key:bytes iv:bytes = DecryptedMessageMedia;
endtoend.17.decryptedMessageMediaAudio#57e0a9cb duration:int mime_type:string size:int key:bytes iv:bytes = DecryptedMessageMedia;
endtoend.17.decryptedMessageLayer#1be31789 random_bytes:bytes layer:int in_seq_no:int out_seq_no:int message:DecryptedMessage = DecryptedMessageLayer;
endtoend.17.decryptedMessageActionResend#511110b0 start_seq_no:int end_seq_no:int = DecryptedMessageAction;
endtoend.17.decryptedMessageActionNotifyLayer#f3048883 layer:int = DecryptedMessageAction;
endtoend.17.decryptedMessageActionTyping#ccb27641 action:SendMessageAction = DecryptedMessageAction;

//===20===
endtoend.20.decryptedMessageActionRequestKey#f3c9611b exchange_id:long g_a:bytes = DecryptedMessageAction;
endtoend.20.decryptedMessageActionAcceptKey#6fe1735b exchange_id:long g_b:bytes key_fingerprint:long = DecryptedMessageAction;
endtoend.20.decryptedMessageActionAbortKey#dd05ec6b exchange_id:long = DecryptedMessageAction;
endtoend.20.decryptedMessageActionCommitKey#ec2e0b9b exchange_id:long key_fingerprint:long = DecryptedMessageAction;
endtoend.20.decryptedMessageActionNoop#a82fdd63 = DecryptedMessageAction;

//===23===
endtoend.23.fileLocationUnavailable#7c596b46 volume_id:long local_id:int secret:long = FileLocation;
endtoend.23.fileLocation#53d69076 dc_id:int volume_id:long local_id:int secret:long = FileLocation;
endtoend.23.decryptedMessageMediaExternalDocument#fa95b0dd id:long access_hash:long date:int mime_type:string size:int thumb:PhotoSize dc_id:int attributes:Vector<DocumentAttribute> = DecryptedMessageMedia;

//===45===
endtoend.45.decryptedMessage#36b091de flags:# random_id:long ttl:int message:string media:flags.9?DecryptedMessageMedia entities:flags.7?Vector<MessageEntity> via_bot_name:flags.11?string reply_to_random_id:flags.3?long = DecryptedMessage;
endtoend.45.decryptedMessageMediaPhoto#f1fa8d78 thumb:bytes thumb_w:int thumb_h:int w:int h:int size:int key:bytes iv:bytes caption:string = DecryptedMessageMedia;
endtoend.45.decryptedMessageMediaVideo#970c8c0e thumb:bytes thumb_w:int thumb_h:int duration:int mime_type:string w:int h:int size:int key:bytes iv:bytes caption:string = DecryptedMessageMedia;
endtoend.45.decryptedMessageMediaDocument#7afe8ae2 thumb:bytes thumb_w:int thumb_h:int mime_type:string size:int key:bytes iv:bytes attributes:Vector<DocumentAttribute> caption:string = DecryptedMessageMedia;
endtoend.45.decryptedMessageMediaVenue#8a0df56f lat:double long:double title:string address:string provider:string venue_id:string = DecryptedMessageMedia;
endtoend.45.decryptedMessageMediaWebPage#e50511d8 url:string = DecryptedMessageMedia;

//===66===

//===73===
endtoend.73.decryptedMessage#91cc4674 flags:# no_webpage:flags.1?true silent:flags.5?true random_id:long ttl:int message:string media:flags.9?DecryptedMessageMedia entities:flags.7?Vector<MessageEntity> via_bot_name:flags.11?string reply_to_random_id:flags.3?long grouped_id:flags.17?long = DecryptedMessage;
