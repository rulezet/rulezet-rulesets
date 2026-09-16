rule mage_cdn_link {
    strings: $ = "\\x6D\\x61\\x67\\x65\\x2D\\x63\\x64\\x6E\\x2E\\x6C\\x69\\x6E\\x6B"
    condition: any of them
}