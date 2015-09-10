<?php

function int64ToBytes($val) {
    $byt = array();
    $byt[0] = ($val & 0xff);
    $byt[1] = ($val >> 8 & 0xff);
    $byt[2] = ($val >> 16 & 0xff);
    $byt[3] = ($val >> 24 & 0xff);
    $byt[4] = ($val >> 32 & 0xff);
    $byt[5] = ($val >> 40 & 0xff);
    $byt[6] = ($val >> 48 & 0xff);
    $byt[7] = ($val >> 56 & 0xff);
    return $byt; 
}
function base64ToBytes($string) {
    $data = base64_decode($string);
    for ($i = 0; $i < strlen($data); ++$i) {
        $bytes[] = ord($data[$i]);
    }
    return $bytes;
}
function concatPayload($playerId, $bundleId, $timestamp, $salt) {
    $bytes = array_merge(
        unpack('C*', $playerId), 
        unpack('C*', $bundleId), 
        int64ToBytes(floatval($timestamp)), 
        base64ToBytes($salt)
    );

    $payload = '';
    foreach ($bytes as $byte) {
        $payload .= chr($byte);
    }
    return $payload;
}
function init() {
    $result = 0;
    do {
        if (!isset($_POST['publicKeyURL'])) {
            break;
        }
        $strm = stream_context_create(array('http' => array('timeout' => 7), 'https' => array('timeout' => 7)));
        $cnt = 0;
        while ($cnt < 3) {
            $pKey = file_get_contents($_POST['publicKeyURL'], false, $strm);
            if ($pKey) {
                break;
            }
            ++$cnt;
        }
        if (!$pKey) {
            break;
        }
        $public_key = "-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($pKey), 64, "\n") . "-----END CERTIFICATE-----";
        $public_key_handle = openssl_get_publickey($public_key);
        $buffer = concatPayload($_POST['playerID'], $_POST['bundleID'], $_POST['timestamp'], $_POST['salt']);
        $result = openssl_verify($buffer, base64_decode($_POST['signature']), $public_key_handle, OPENSSL_ALGO_SHA256);
    } while(false);
    if (1 == $result) {
        $Result['ret'] = 0;
    }
    else {
        $Result['ret'] = 1;
    }
    echo json_encode($Result);
}
init();
?>
