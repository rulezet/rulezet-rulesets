rule md5_0105d05660329704bdb0ecd3fd3a473b {
    
    strings: $ = /\)\s*\)\s*\{\s*eval\s*\(\s*\$\{/
    condition: any of them
}