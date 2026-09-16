rule sig_20161208_9244c56c8d37a34bb6ac60fe59113653 {
  meta:
    description = "datamaliciousorder - file 20161208_9244c56c8d37a34bb6ac60fe59113653.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b57c2117e40016b038f41ff57ca4886cc1086decda2748e453b8abd20b0b8adc"

  strings:
    $s1 = "var vCMe2 = new Function(\"vMGx9\", '{return vMGx9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRy4 = new Function(\"vMG" ascii
    $s2 = " = new Date();vOp7[\"setUTC\"+\"FullYear\"](\"2003\");if (vOp7.getUTCFullYear().toString(10) == \"2003\") {var vAQt2 = vMGx9.spl" ascii
    $s3 = "\"); return vAQt2.join(\"\");} else return \"\";}');" fullword ascii
    $s4 = "var vCMe2 = new Function(\"vMGx9\", '{return vMGx9[\"sp\"+\"lit\"](\",\")[\"jo\"+\"in\"](\"\");}');var vRy4 = new Function(\"vMG" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}