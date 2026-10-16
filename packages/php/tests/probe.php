<?php
// What this PHP lets a program do, as one JSON line; tests/probe.sh compares it
// with the protections in patches/series and the image's allowances.
$result = [
    'exec' => function_exists('system'),                               // php:exec
    'native' => function_exists('dl'),                                 // php:native
    'deserialize' => unserialize('O:8:"stdClass":0:{}') instanceof stdClass,  // php:deserialize
    'phar' => in_array('phar', stream_get_wrappers(), true),           // always absent
    'phar_class' => class_exists('Phar', false),
    'phar_extension' => extension_loaded('phar'),
];
ksort($result);
echo json_encode($result), "\n";
