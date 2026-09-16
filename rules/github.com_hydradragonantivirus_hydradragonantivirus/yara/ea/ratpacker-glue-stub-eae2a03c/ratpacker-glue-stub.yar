import "pe"
rule RatPacker__Glue__stub {
  strings:
    $a0 = { 40 20 FF ?? ?? ?? ?? ?? ?? ?? ?? BE ?? 60 40 ?? 8D BE ?? B0 FF FF }
    $a1 = { 40 20 FF 00 00 00 00 00 00 00 ?? BE 00 60 40 00 8D BE 00 B0 FF FF }

  condition:
    $a0 at pe.entry_point or $a1 at pe.entry_point
}