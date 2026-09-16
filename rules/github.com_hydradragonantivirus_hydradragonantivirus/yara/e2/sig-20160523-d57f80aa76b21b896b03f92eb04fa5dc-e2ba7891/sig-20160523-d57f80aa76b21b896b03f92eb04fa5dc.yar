rule sig_20160523_d57f80aa76b21b896b03f92eb04fa5dc {
  meta:
    description = "datamaliciousorder - file 20160523_d57f80aa76b21b896b03f92eb04fa5dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "598a9270f9654df6433fffe106b1752d60c7995b6c1a0b6fe182f95220021b9d"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "            var fileObj = fso.GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check" ascii
    $s3 = " = ts.ReadAll();                 eval(check);                               ts.Close();                     }                mai" ascii
    $s4 = "oKGUpe307ICAgICAgICAgICAgICAgICAg';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdh" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}