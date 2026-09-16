import "pe"
rule _Turbo_Pascal_Help_File_ {
  meta:
    description = "Turbo Pascal Help File"

  strings:
    $0 = { 54 55 52 ?? ?? ?? 50 41 53 ?? ?? ?? ?? 48 45 4C 50 }

  condition:
    $0 at pe.entry_point
}