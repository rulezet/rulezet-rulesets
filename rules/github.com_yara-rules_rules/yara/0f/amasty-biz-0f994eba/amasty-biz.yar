rule amasty_biz {
    strings: $ = "118,97,114,32,115,110,100,32,61,110,117,108,108,59,10,10,102,117"
    condition: any of them
}