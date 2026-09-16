rule sig_20160523_d4f056d8a78917ca73748037a3ec2948 {
  meta:
    description = "datamaliciousorder - file 20160523_d4f056d8a78917ca73748037a3ec2948.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462822cb5929d771c38d27352085d97a7d5ed498d23168d1cf777059b150c305"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "           var check = ts.ReadAll();                 eval(check);                               ts.Close();                     " ascii
    $s3 = "2NS5leGUnLCAxKX1jYXRjaChlKXt9OyAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}