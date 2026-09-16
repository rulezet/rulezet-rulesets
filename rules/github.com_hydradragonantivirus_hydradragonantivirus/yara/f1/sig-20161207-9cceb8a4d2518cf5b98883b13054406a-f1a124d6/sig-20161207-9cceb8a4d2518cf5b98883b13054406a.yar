rule sig_20161207_9cceb8a4d2518cf5b98883b13054406a {
  meta:
    description = "datamaliciousorder - file 20161207_9cceb8a4d2518cf5b98883b13054406a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c134f563f2d7e876c44269f0a476bb070f208d77ae3e8a1d7d664ecb5c3835b"

  strings:
    $s1 = "var vUUe2 = new Function(\"vXOe9\", '{var vVGi9 = new Date();vVGi9[\"setUTCFullYear\"](\"2003\");if (vVGi9.getUTCFullYear().toSt" ascii
    $s2 = "var vUUe2 = new Function(\"vXOe9\", '{var vVGi9 = new Date();vVGi9[\"setUTCFullYear\"](\"2003\");if (vVGi9.getUTCFullYear().toSt" ascii
    $s3 = "var vBJi6 = new Function(\"vXOe9\", '{return vXOe9.split(\",\").join(\"\");};');" fullword ascii
    $s4 = "0) == \"2003\") {var vDLh9 = vXOe9.split(\"###\"); return vDLh9.join(\"\");} else return \"\";};');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}