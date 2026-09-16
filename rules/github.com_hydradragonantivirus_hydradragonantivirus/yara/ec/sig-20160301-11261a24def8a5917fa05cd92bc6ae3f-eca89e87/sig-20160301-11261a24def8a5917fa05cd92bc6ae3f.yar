rule sig_20160301_11261a24def8a5917fa05cd92bc6ae3f {
  meta:
    description = "datamaliciousorder - file 20160301_11261a24def8a5917fa05cd92bc6ae3f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffdcc5d3a91198c4cb5a795adf2c822b53d2293ff0dd5e798886ff9fb15dab39"

  strings:
    $s1 = "while (industryVoyage[(\"r\\u0065anima\\u0074\\u0069o\\u006e\", \"readystat\\u0065\")] < ((0 | 4) + (12 - 12))) {" fullword ascii
    $s2 = "} catch (categoryManuscript) {};" fullword ascii
    $s3 = "modalAssembly = (((1596 / 4) / (12 ^ 31)), this);" fullword ascii
    $s4 = "industryVoyage[(\"i\\u006dpr\\u0065s\\u0073\\u0069\\u006f\\u006e\", function String.prototype.assemblyRegistry() {" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    all of them
}