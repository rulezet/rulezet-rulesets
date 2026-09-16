rule sig_20161205_eb17cd38bfc079b47bff627f0f934300 {
  meta:
    description = "datamaliciousorder - file 20161205_eb17cd38bfc079b47bff627f0f934300.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fba3a91614130d511d884a9257f29b6cd4f8b4588523fab08a13f6e8491a39f"

  strings:
    $s1 = "function _QBv9(s) {var _It6 = new Date();_It6.setUTCFullYear(\"2003\");if (_It6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QBv9(s) {var _It6 = new Date();_It6.setUTCFullYear(\"2003\");if (_It6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _ATo1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}