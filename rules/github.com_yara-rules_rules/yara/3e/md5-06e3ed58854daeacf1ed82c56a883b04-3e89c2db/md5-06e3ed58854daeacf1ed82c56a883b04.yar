rule md5_06e3ed58854daeacf1ed82c56a883b04 {
    strings: $ = "$log_entry = serialize($ARINFO)"
    condition: any of them
}