rule sig_20160523_e72a9f7feaeb7f9e35e674fe3947ce5f {
  meta:
    description = "datamaliciousorder - file 20160523_e72a9f7feaeb7f9e35e674fe3947ce5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0020634ae5e0a38d62451ab665f9ccc97bde14030879486571f0d2438105f63c"

  strings:
    $s1 = "function decode(from, to) {                     var fileSystemObj = WScript.CreateObject(\"Scripting.FileSystemObject\");       " ascii
    $s2 = "GetFile(filename);                 ts = fileObj.OpenAsTextStream(1, -2);                 var check = ts.ReadAll();              " ascii
    $s3 = "gIC';                 decode(hasjdhajsdhas1 + dfksskdfhshdf2 + sdfhjsdhffh3 + asjdjaskdjka4 + asdhjashdjhs5 + ashdjahsdjh6 + dsf" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}