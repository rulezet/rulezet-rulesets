rule fake_magentoupdate_site {
    strings: $ = "magentopatchupdate.com"
    condition: any of them
}