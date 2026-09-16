import "pe"
rule PEiD_00355_Borland_Pascal_v7_0_ {
  meta:
    description = "[Borland Pascal v7.0]"
    ep_only     = "true"

  strings:
    $a = { B8 ?? ?? 8E D8 8C ?? ?? ?? 8C D3 8C C0 2B D8 8B C4 05 ?? ?? C1 ?? ?? 03 D8 B4 ?? CD 21 0E }

  condition:
    $a at pe.entry_point
}