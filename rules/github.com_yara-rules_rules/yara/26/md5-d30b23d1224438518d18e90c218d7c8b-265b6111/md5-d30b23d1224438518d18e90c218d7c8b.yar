rule md5_d30b23d1224438518d18e90c218d7c8b {
    strings: $ = "attribute_code=0x70617373776f72645f68617368"
    condition: any of them
}