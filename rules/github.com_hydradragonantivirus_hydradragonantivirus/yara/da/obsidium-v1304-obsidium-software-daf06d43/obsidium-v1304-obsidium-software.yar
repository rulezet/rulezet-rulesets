import "pe"
rule _Obsidium_V1304__Obsidium_Software_ {
  meta:
    description = "Obsidium V1.3.0.4 -> Obsidium Software"

  strings:
    $0 = { EB 02 ?? ?? E8 ?? 00 00 00 }

  condition:
    $0 at pe.entry_point
}