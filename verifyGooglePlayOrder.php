<?php

function init() {
    $public_key = "-----BEGIN PUBLIC KEY-----\n" . chunk_split($_POST['key'], 64, "\n") . "-----END PUBLIC KEY-----";
    $public_key_handle = openssl_get_publickey($public_key);
    $result = openssl_verify($_POST['data'], base64_decode($_POST['sign']), $public_key_handle, OPENSSL_ALGO_SHA1);
    if (1 === $result) {
        // 支付验证成功！
        $Result['ret'] = 0;
    }
    else {
        $Result['ret'] = 1;
    }
    echo json_encode($Result);
}

init();
?>
