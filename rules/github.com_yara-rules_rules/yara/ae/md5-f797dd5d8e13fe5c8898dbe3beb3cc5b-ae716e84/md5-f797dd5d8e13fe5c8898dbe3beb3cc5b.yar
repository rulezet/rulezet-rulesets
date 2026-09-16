rule md5_f797dd5d8e13fe5c8898dbe3beb3cc5b {
    strings: $ = "echo(\"FILE_Bad\");"
    condition: any of them
}