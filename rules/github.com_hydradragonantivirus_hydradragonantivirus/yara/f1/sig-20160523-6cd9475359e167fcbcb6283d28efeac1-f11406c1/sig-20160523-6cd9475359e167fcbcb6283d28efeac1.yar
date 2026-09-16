rule sig_20160523_6cd9475359e167fcbcb6283d28efeac1 {
  meta:
    description = "datamaliciousorder - file 20160523_6cd9475359e167fcbcb6283d28efeac1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c79cfeec4da677f47108907d1fdf61328621f32eb1e8b41e3498e1ebf7ae1a03"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();              " ascii
    $s3 = "gIC';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdhjashdjhs5 + ashdjahsdjh6 + dsf" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}