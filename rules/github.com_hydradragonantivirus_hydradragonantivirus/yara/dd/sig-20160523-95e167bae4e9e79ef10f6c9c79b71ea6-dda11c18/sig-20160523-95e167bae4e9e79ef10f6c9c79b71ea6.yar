rule sig_20160523_95e167bae4e9e79ef10f6c9c79b71ea6 {
  meta:
    description = "datamaliciousorder - file 20160523_95e167bae4e9e79ef10f6c9c79b71ea6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfd7c74f6ee38cf657cb609d4a3cbd8f0bcd2bf22f9ebfc62470fb39ae24bc6a"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "           var check = ts.ReadAll();                 eval(check);                               ts.Close();                     " ascii
    $s3 = "2Ny5leGUnLCAxKX1jYXRjaChlKXt9OyAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}