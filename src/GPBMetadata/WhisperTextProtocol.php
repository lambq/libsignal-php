<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: WhisperTextProtocol.proto

namespace GPBMetadata;

class WhisperTextProtocol
{
    public static $is_initialized = false;

    public static function initOnce() {
        $pool = \Google\Protobuf\Internal\DescriptorPool::getGeneratedPool();

        if (static::$is_initialized == true) {
          return;
        }
        $pool->internalAddGeneratedFile(
            '
�
WhisperTextProtocol.protowhispertext"�
WhisperMessage

ratchetKey (H �
counter (H�
previousCounter (H�

ciphertext (H�B
_ratchetKeyB

_counterB
_previousCounterB
_ciphertext"�
PreKeyWhisperMessage
registrationId (H �
preKeyId (H�
signedPreKeyId (H�
baseKey (H�
identityKey (H�
message (H�B
_registrationIdB
	_preKeyIdB
_signedPreKeyIdB

_baseKeyB
_identityKeyB

_message"�
KeyExchangeMessage
id (H �
baseKey (H�

ratchetKey (H�
identityKey (H�
baseKeySignature (H�B
_idB

_baseKeyB
_ratchetKeyB
_identityKeyB
_baseKeySignature"x
SenderKeyMessage
id (H �
	iteration (H�

ciphertext (H�B
_idB

_iterationB
_ciphertext"�
SenderKeyDistributionMessage
id (H �
	iteration (H�
chainKey (H�

signingKey (H�B
_idB

_iterationB
	_chainKeyB
_signingKeyB7
&org.whispersystems.libaxolotl.protocolBWhisperProtosbproto3'
        , true);

        static::$is_initialized = true;
    }
}

