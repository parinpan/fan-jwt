<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitdd18ce504ec76a965e8f1b08619da20f
{
    public static $prefixLengthsPsr4 = array (
        'p' => 
        array (
            'parinpan\\fanjwt\\' => 16,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'parinpan\\fanjwt\\' => 
        array (
            0 => __DIR__ . '/../..' . '/',
        ),
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitdd18ce504ec76a965e8f1b08619da20f::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitdd18ce504ec76a965e8f1b08619da20f::$prefixDirsPsr4;

        }, null, ClassLoader::class);
    }
}
