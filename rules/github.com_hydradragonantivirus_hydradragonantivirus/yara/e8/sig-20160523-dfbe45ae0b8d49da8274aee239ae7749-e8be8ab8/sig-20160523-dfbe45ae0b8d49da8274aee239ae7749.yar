rule sig_20160523_dfbe45ae0b8d49da8274aee239ae7749 {
  meta:
    description = "datamaliciousorder - file 20160523_dfbe45ae0b8d49da8274aee239ae7749.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c9fc25cadc2dd9533ddd2e2a5b3b7ce69d6ae8fee4c21e81681f64b76cf4ce6"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "            var fileObj = fso.GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check" ascii
    $s3 = " = ts.ReadAll();                 eval(check);                               ts.Close();                     }                mai" ascii
    $s4 = "oKGUpe307ICAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdh" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}