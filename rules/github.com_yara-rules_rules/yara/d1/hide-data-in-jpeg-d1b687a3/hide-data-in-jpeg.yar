rule hide_data_in_jpeg {
    strings: $ = /file_put_contents\(\$.{2,3},'JPEG-1\.1'\.base64_encode/
    condition: any of them
}