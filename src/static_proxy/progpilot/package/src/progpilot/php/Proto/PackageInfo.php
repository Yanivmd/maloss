<?php
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: info.proto

namespace Proto;

use Google\Protobuf\Internal\GPBType;
use Google\Protobuf\Internal\RepeatedField;
use Google\Protobuf\Internal\GPBUtil;

/**
 * Generated from protobuf message <code>proto.PackageInfo</code>
 */
class PackageInfo extends \Google\Protobuf\Internal\Message
{
    /**
     * Generated from protobuf field <code>.proto.PackageInfo.Metadata info = 1;</code>
     */
    private $info = null;
    /**
     * Runtime dependencies
     *
     * Generated from protobuf field <code>repeated .proto.PackageInfo.Metadata dependencies = 2;</code>
     */
    private $dependencies;
    /**
     * Development dependencies
     *
     * Generated from protobuf field <code>repeated .proto.PackageInfo.Metadata dev_dependencies = 3;</code>
     */
    private $dev_dependencies;

    /**
     * Constructor.
     *
     * @param array $data {
     *     Optional. Data for populating the Message object.
     *
     *     @type \Proto\PackageInfo\Metadata $info
     *     @type \Proto\PackageInfo\Metadata[]|\Google\Protobuf\Internal\RepeatedField $dependencies
     *           Runtime dependencies
     *     @type \Proto\PackageInfo\Metadata[]|\Google\Protobuf\Internal\RepeatedField $dev_dependencies
     *           Development dependencies
     * }
     */
    public function __construct($data = NULL) {
        \GPBMetadata\Info::initOnce();
        parent::__construct($data);
    }

    /**
     * Generated from protobuf field <code>.proto.PackageInfo.Metadata info = 1;</code>
     * @return \Proto\PackageInfo\Metadata
     */
    public function getInfo()
    {
        return $this->info;
    }

    /**
     * Generated from protobuf field <code>.proto.PackageInfo.Metadata info = 1;</code>
     * @param \Proto\PackageInfo\Metadata $var
     * @return $this
     */
    public function setInfo($var)
    {
        GPBUtil::checkMessage($var, \Proto\PackageInfo_Metadata::class);
        $this->info = $var;

        return $this;
    }

    /**
     * Runtime dependencies
     *
     * Generated from protobuf field <code>repeated .proto.PackageInfo.Metadata dependencies = 2;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getDependencies()
    {
        return $this->dependencies;
    }

    /**
     * Runtime dependencies
     *
     * Generated from protobuf field <code>repeated .proto.PackageInfo.Metadata dependencies = 2;</code>
     * @param \Proto\PackageInfo\Metadata[]|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setDependencies($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Proto\PackageInfo\Metadata::class);
        $this->dependencies = $arr;

        return $this;
    }

    /**
     * Development dependencies
     *
     * Generated from protobuf field <code>repeated .proto.PackageInfo.Metadata dev_dependencies = 3;</code>
     * @return \Google\Protobuf\Internal\RepeatedField
     */
    public function getDevDependencies()
    {
        return $this->dev_dependencies;
    }

    /**
     * Development dependencies
     *
     * Generated from protobuf field <code>repeated .proto.PackageInfo.Metadata dev_dependencies = 3;</code>
     * @param \Proto\PackageInfo\Metadata[]|\Google\Protobuf\Internal\RepeatedField $var
     * @return $this
     */
    public function setDevDependencies($var)
    {
        $arr = GPBUtil::checkRepeatedField($var, \Google\Protobuf\Internal\GPBType::MESSAGE, \Proto\PackageInfo\Metadata::class);
        $this->dev_dependencies = $arr;

        return $this;
    }

}

