rule eval_base64_decode_a {
    strings: $ = "eval(base64_decode($a));"
    condition: any of them
}