rule md5_28690a72362e021f65bb74eecc54255e {
    strings: $ = "curl_setopt($ch, CURLOPT_POSTFIELDS,http_build_query(array('data'=>$data,'utmp'=>$id)));"
    condition: any of them
}