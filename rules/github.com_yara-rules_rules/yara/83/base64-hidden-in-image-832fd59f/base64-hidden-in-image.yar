rule base64_hidden_in_image {
    strings: $ = /JPEG-1\.1[a-zA-Z0-9\-\/]{32}/
    condition: any of them
}