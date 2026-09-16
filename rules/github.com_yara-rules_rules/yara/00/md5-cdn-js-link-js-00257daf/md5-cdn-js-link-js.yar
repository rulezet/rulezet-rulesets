rule md5_cdn_js_link_js {
    strings: $ = "grelos_v= null"
    condition: any of them
}