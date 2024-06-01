<?php

/**
 * 
 * Ensure that the required JOSE components are installed using Composer.
 * 
 * Run the below command line in your project directory to install the JOSE library:
 * >> composer require web-token/jwt-core web-token/jwt-signature web-token/jwt-signature-algorithm-hmac 
 *
 * Autoload: The script includes the Composer autoloader.
 * 
 * Dependencies: It imports necessary classes from the JOSE library.
 *
 * Last Modified: Divyansh on June 1, 2024
 */

require 'vendor/autoload.php';

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Core\JWK;


$jsonString = '{"user_id": 2222, "username": "john_doe"}';

$base64EncodedSecretKey = 'AQY83aLVgfxWTKpXczZEx/HZoVH7w+wuvOMdeJZW2Ic=='; // Your base64 encoded secret key

try {
    $signedJwt = signJsonString($jsonString, $base64EncodedSecretKey);

       $arr = explode(".", trim($signedJwt));

    echo "Signed JWT: " . trim($signedJwt); 
    echo "\nJWS Signature: \n" . $arr[0] . "." . "." . $arr[2] . "\n";


} catch (Exception $e) {
    echo 'Error: ' . $e->getMessage();
}
// Function to sign JSON string using HS256
function signJsonString($jsonString, $base64EncodedSecretKey) {

    // Decode the JSON string to an associative array
    $payload = json_decode($jsonString, true);

    // Check if json_decode failed
    if (json_last_error() !== JSON_ERROR_NONE) {
        throw new InvalidArgumentException('Invalid JSON string provided');
    }

    // Ensure the base64-encoded secret key is URL-safe and without padding
    $base64UrlSafeSecretKey = rtrim(strtr($base64EncodedSecretKey, '+/', '-_'), '=');

    // Decode the base64-url-encoded secret key
    $secretKey = base64_decode(strtr($base64UrlSafeSecretKey, '-_', '+/'));

    // Create the key
    $jwk = new JWK([
        'kty' => 'oct',
        'k' => $base64UrlSafeSecretKey, // Directly use the URL-safe base64 encoded key
    ]);

    // The algorithm manager with only the HS256 algorithm
    $algorithmManager = new AlgorithmManager([
        new HS256(),
    ]);

    // Our JWS Builder
    $jwsBuilder = new JWSBuilder($algorithmManager);

    // Create the JWS
    $jws = $jwsBuilder
        ->create()                               // We want to create a new JWS
        ->withPayload(json_encode($payload))     // We set the payload
        ->addSignature($jwk, ['alg' => 'HS256']) // We add a signature with the key and algorithm
        ->build();                               // We build it

    // The Compact Serializer
    $serializer = new CompactSerializer(); // The serializer

    // We serialize the JWS to compact JSON serialization
    $token = $serializer->serialize($jws);

    return $token;
}


?>
