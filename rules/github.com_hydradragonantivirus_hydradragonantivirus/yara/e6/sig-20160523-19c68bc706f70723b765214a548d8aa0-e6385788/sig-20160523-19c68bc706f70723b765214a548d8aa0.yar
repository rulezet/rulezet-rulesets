rule sig_20160523_19c68bc706f70723b765214a548d8aa0 {
  meta:
    description = "datamaliciousorder - file 20160523_19c68bc706f70723b765214a548d8aa0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e397ff0e1ee1579f8000f5d63e1446e38c7686d109089710aeaab486c35b9828"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "= fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();                 eval(check);                       " ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}