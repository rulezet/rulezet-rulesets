rule sig_20160517_39646bf0d1d89b93eec67a5975b97e72 {
  meta:
    description = "datamaliciousorder - file 20160517_39646bf0d1d89b93eec67a5975b97e72.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86403c0fe590756c1350e86fe5ff752a5d3b227bed232eb4a27b331d64803b9b"

  strings:
    $s1 = "var cfreyj='vu24itadjsfmrolxli jqesina3phnesrnpkwifmurksob3xxwcjprevbiay4pm2kxudlpba=exjqr\\'g1fg4tb3grrcvnxksnffewtilkewqfi1nwq" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}