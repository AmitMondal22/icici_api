<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;
use phpseclib\Crypt\RSA;
use Illuminate\Support\Facades\Crypt;



class FetchApi extends Controller
{
    public function index(Request $r)
    {


        // API endpoint
        $url = "https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/AccountStatements";

        // UAT credentials
        $credentials = array(
            "AGGRID" => "OTOE0613",
            "AGGRNAME" => "PURI",
            "CORPID" => "SESPRODUCT",
            "USERID" => "389018",
            "URN" => "SR232890806",
            "ACCOUNTNO" => "000405001611",
            "FROMDATE" => "01-01-2016",
            "TODATE" => "30-12-2016"
        );

        // API key
        $headers = array(
            "APIKEY: eM8xAWGQxHFOnEgzT93egz7HzGRc8mGf",
            "Content-Type: text/plain"
        );

        // Encryption and decryption settings
        $public_key = file_get_contents(public_path('ICICIpurdcs/Password.txt'));
        $private_key = file_get_contents("client_private.key");
        $session_key_algorithm = "RSA/ECB/PKCS1Padding";
        $data_algorithm = "AES-128-CBC";
        $data_mode = "CBC";
        $data_padding = "PKCS5Padding";

        // Prepare data to be encrypted
        $data = http_build_query($credentials);

        // Generate a random session key
        $session_key = openssl_random_pseudo_bytes(16);

        // Encrypt the session key using the bank's public key
        $encrypted_session_key = "";
        openssl_public_encrypt($session_key, $encrypted_session_key, $public_key, OPENSSL_PKCS1_PADDING);
        $encrypted_session_key = base64_encode($encrypted_session_key);

        // Encrypt the data using the session key
        $iv = openssl_random_pseudo_bytes(16);
        $encrypted_data = openssl_encrypt($data, $data_algorithm, $session_key, OPENSSL_RAW_DATA, $iv);
        $encrypted_data = $iv . $encrypted_data;
        $encrypted_data = base64_encode($encrypted_data);

        // Build the request body
        $request_body = "SESSION_KEY=$encrypted_session_key&DATA=$encrypted_data";

        // Make the API call
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $request_body);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        $response = curl_exec($ch);
        curl_close($ch);

        // Decrypt the response
        $response = json_decode($response, true);
        $encrypted_session_key = base64_decode($response["SESSION_KEY"]);
        $encrypted_data = base64_decode($response["DATA"]);

        // Decrypt the session key using the client's private key
        $session_key = "";
        openssl_private_decrypt($encrypted_session_key, $session_key, $private_key, OPENSSL_PKCS1_PADDING);

        // Decrypt the data using the session key
        $iv = substr($encrypted_data, 0, 16);
        $encrypted_data = substr($encrypted_data, 16);
        $data = openssl_decrypt($encrypted_data, $data_algorithm, $session_key, OPENSSL_RAW_DATA, $iv);
        $data = urldecode($data);
        $data = json_decode($data, true);

        // Display the result
        print_r($data);
    }

    public function test_i()
    {
        $request = [
            "AGGRID" => "OTOE0613",
            "AGGRNAME" => "PURI",
            "CORPID" => "SESPRODUCT",
            "USERID" => "389018",
            "URN" => "SR232890806",
            "ACCOUNTNO" => "000405001611",
            "FROMDATE" => "01-01-2016",
            "TODATE" => "30-12-2016",
        ];
        $header = [
            'accept: */*',
            'APIKEY: eM8xAWGQxHFOnEgzT93egz7HzGRc8mGf',
            'content-length: 684',
            'content-type: text/plain'
        ];




        $fp = fopen(public_path('ICICIpurdcs/icici_purdcs_com.pem'), "r");
        $pub_key_string = fread($fp, 8192);
        fclose($fp);
        // openssl_get_publickey($pub_key);
        openssl_public_encrypt(json_encode($request), $crypttext, $pub_key_string);

        $enc = base64_encode($crypttext);
        $final_request = json_encode($enc);


        $url = 'https://apibankingonesandbox.icicibank.com/api/Corporate/CIB/v1/AccountStatements';


        $curl = curl_init();
        curl_setopt_array(
            $curl,
            array(
                CURLOPT_PORT => "8443",
                CURLOPT_URL => $url,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_ENCODING => "",
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 120,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => "POST",
                CURLOPT_POSTFIELDS => $final_request,
                CURLOPT_HTTPHEADER => $header
            )
        );
        $response = curl_exec($curl);
        $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $err = curl_error($curl);
        curl_close($curl);


        return $response;
        $httpcode;
        $fp = fopen(public_path('ICICIpurdcs/Private Key.pem'), "r");
        $private_key = fread($fp, 8192);
        fclose($fp);
        $private_key;
        $private_key = openssl_get_privatekey($private_key, "");
        openssl_private_decrypt(base64_decode($response), $resp, $private_key);
        return $resp;
    }
}







// ini_set('display_errors',1);
// $p = [];
// $p["AGGRID"]="AGGR0051";
// $p["CORPID"]="PRACHICIB1";
// $p["USERID"]="USER3";
// $p["URN"]="1111";
// $p["AGGRNAME"]="EVOLVE";
// $p['ALIASID'] ="";
// $httpUrl ="Enter your white listed IP here";
// $request = [ "CORPID" => $p["CORPID"],
//             "USERID" => $p["USERID"], 
//             "AGGRNAME" => $p["AGGRNAME"],
//             "AGGRID" => $p["AGGRID"],
//             "URN" => $p["URN"], ]; 
// if(isset($p['ALIASID'])){
//     $request['ALIASID'] = $p['ALIASID']; 
// } 
// $header = [ 'apikey:aaaaaa', 'Content-type:text/plain' ];
// $url = 'https://apigwuat.icicibank.com:8443/api/Corporate/CIB/v1/Registration';

// $fp=fopen("cibnextapiuat.txt","r");
// $pub_key_string=fread($fp,8192);
// fclose($fp); 
// // openssl_get_publickey($pub_key);
// openssl_public_encrypt(json_encode($request),$crypttext,$pub_key_string);

// $enc = base64_encode($crypttext);
// $final_request = json_encode($enc);
// $url;
// $curl = curl_init();
// curl_setopt_array($curl, 
//     array( CURLOPT_PORT => "8443",
//             CURLOPT_URL => $url,
//             CURLOPT_RETURNTRANSFER => true,
//             CURLOPT_ENCODING => "",
//             CURLOPT_MAXREDIRS => 10,
//             CURLOPT_TIMEOUT => 120,
//             CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
//             CURLOPT_CUSTOMREQUEST => "POST",
//             CURLOPT_POSTFIELDS => $final_request,
//             CURLOPT_HTTPHEADER => $header 
//     )
// ); 
// $response = curl_exec($curl);
// $httpcode = curl_getinfo($curl, CURLINFO_HTTP_CODE);
// $err = curl_error($curl);
// curl_close($curl);
// $response;
// $httpcode; 
// $fp=fopen("privatekey.pem","r");
// $private_key=fread($fp,8192);
// fclose($fp);
// $private_key;
// $private_key = openssl_get_privatekey($private_key, "");
// openssl_private_decrypt(base64_decode($response), $resp, $private_key);
// echo $resp; 


// $response => "is the encrypted response you get agter hittig API"
//  DecryptData => "is the decryption code which I coded on your laptop" ;
// $resp = json_decode($response); 
// $data = base64_decode($resp->encryptedData); 
// $iv = substr($data,0,16); 
// $key = $this->DecryptData($resp->encryptedKey); 
// if(16 !== strlen($key)) $key = hash('MD5', $key, true); 
// $data = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, str_repeat("\0", 16)); 
// $padding = ord($data[strlen($data) - 1]); 
// $response = substr($data, 0, -$padding); 
// $response = substr($response, 16); $this->output .= "\r\n";
// $this->output .= $response; $output->response = $response;