rule md5_d201d61510f7889f1a47257d52b15fa2 {
    strings: $ = "@eval(stripslashes($_REQUEST[q]));"
    condition: any of them
}