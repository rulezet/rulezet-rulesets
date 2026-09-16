rule sig_20160523_9f2c8f32fcafb7e023bc13614ecf5104 {
  meta:
    description = "datamaliciousorder - file 20160523_9f2c8f32fcafb7e023bc13614ecf5104.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e38f12503569d4ef01cc9113a529f870c6956f5059ed73b0081a9966e992f5d"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "= fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();                 eval(check);                       " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}