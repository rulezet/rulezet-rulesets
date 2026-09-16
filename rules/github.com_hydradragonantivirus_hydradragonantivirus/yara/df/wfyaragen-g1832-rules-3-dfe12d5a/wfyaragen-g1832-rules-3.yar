rule WFYARAGEN_G1832_rules_3 {
  meta:
    description = "Matches file used in various infections"

  strings:
    $re = /^0\.5\.2\.2\s*?0\.83\.4\.1\s+?1\.0\.145\.2\s+?1\.0\.145\.210\s+?1\.0\.177\.126/ nocase

  condition:
    $re
}