<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: LocalStorageProtocol.proto

namespace Localstorage;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>localstorage.RecordStructure</code>
 */
class RecordStructure extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>optional .localstorage.SessionStructure currentSession = 1;</code>
     */
    protected $currentSession = null;
    /**
     * Generated from protobuf field <code>repeated .localstorage.SessionStructure previousSessions = 2;</code>
     */
    private $previousSessions;

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type \Localstorage\SessionStructure $currentSession
     *     @type \Localstorage\SessionStructure[]|\Google\Protobuf\Internal\RepeatedField $previousSessions
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\LocalStorageProtocol::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>optional .localstorage.SessionStructure currentSession = 1;</code>
     * @return \Localstorage\SessionStructure|null
     */
    public function getCurrentSession()
    {
        return isset($this->currentSession) ? $this->currentSession : null;
    }

    public function hasCurrentSession()
    {
        return isset($this->currentSession);
    }

    public function clearCurrentSession()
    {
        unset($this->currentSession);
    }

    /**
     * Generated from protobuf field <code>optional .localstorage.SessionStructure currentSession = 1;</code>
     * @param \Localstorage\SessionStructure $var
     * @return $this
     */
    public function setCurrentSession($var)
    {
        GPBUtil::checkMessage($var, \Localstorage\SessionStructure::class);
        $this->currentSession = $var;

        return $this;
    }

    /**
     * Generated from protobuf field <code>repeated .localstorage.SessionStructure previousSessions = 2;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getPreviousSessions()
    {
        return $this->previousSessions;
    }

    /**
     * Generated from protobuf field <code>repeated .localstorage.SessionStructure previousSessions = 2;</code>
     * @param \Localstorage\SessionStructure[]|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setPreviousSessions($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Localstorage\SessionStructure::class);
        $this->previousSessions = $arr;

        return $this;
    }

}
