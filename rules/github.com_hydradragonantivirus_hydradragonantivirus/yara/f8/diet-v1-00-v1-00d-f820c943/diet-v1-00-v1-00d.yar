import "pe"
rule DIET_v1_00__v1_00d {
  strings:
    $a0 = { BF ?? ?? 3B FC 72 ?? B4 4C CD 21 BE ?? ?? B9 ?? ?? FD F3 A5 FC }

  condition:
    $a0 at pe.entry_point
}