import "pe"
rule PEiD_02159_Stony_Brook_Pascal_v6_14_ {
  meta:
    description = "[Stony Brook Pascal v6.14]"
    ep_only     = "true"

  strings:
    $a = { 31 ED 9A ?? ?? ?? ?? 55 89 E5 ?? EC ?? ?? 9A }

  condition:
    $a at pe.entry_point
}