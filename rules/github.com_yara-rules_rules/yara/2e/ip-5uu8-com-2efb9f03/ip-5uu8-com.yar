rule ip_5uu8_com {
    strings: $ = "\\x69\\x70\\x2e\\x35\\x75\\x75\\x38\\x2e\\x63\\x6f\\x6d"
    condition: any of them
}