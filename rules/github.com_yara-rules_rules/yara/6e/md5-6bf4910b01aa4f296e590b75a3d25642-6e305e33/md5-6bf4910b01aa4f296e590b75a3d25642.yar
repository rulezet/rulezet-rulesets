rule md5_6bf4910b01aa4f296e590b75a3d25642 {
    strings: $ = "base64_decode('b25lcGFnZXxnY19hZG1pbg==')"
    condition: any of them
}