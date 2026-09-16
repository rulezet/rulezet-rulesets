rule sig_20161208_540ed7be6ee93babd9fdb5777dbe0e3a {
  meta:
    description = "datamaliciousorder - file 20161208_540ed7be6ee93babd9fdb5777dbe0e3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9db4b14813cebf4a3dce8d4873a53cd3eeae32eead8cf080b93bcc7b659fa73"

  strings:
    $s1 = "ew Date();vBt9[\"setUTC\"+\"FullYear\"](\"2003\");if (vBt9.getUTCFullYear().toString(10) == \"2003\") {var vNNe4 = vNd0.split(\"" ascii
    $s2 = "var vZg8 = new Function(\"vNd0\", '{return vNd0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVk7 = new Function(\"vNd0\"" ascii
    $s3 = "var vZg8 = new Function(\"vNd0\", '{return vNd0[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vVk7 = new Function(\"vNd0\"" ascii
    $s4 = "eturn vNNe4.join(\"\");} else return \"\";}');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}