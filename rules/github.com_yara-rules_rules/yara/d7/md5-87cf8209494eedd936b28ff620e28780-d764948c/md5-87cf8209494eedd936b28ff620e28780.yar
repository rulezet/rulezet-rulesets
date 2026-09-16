rule md5_87cf8209494eedd936b28ff620e28780 {
    strings: $ = "curl_close($cu);eval($o);};die();"
    condition: any of them
}