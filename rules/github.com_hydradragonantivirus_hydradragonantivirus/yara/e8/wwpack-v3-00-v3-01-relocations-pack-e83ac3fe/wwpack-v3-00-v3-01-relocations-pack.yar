import "pe"
rule WWPACK_v3_00__v3_01__Relocations_pack_ {
  strings:
    $a0 = { BE ?? ?? BA ?? ?? BF ?? ?? B9 ?? ?? 8C CD 8E DD 81 ED ?? ?? 06 06 8B DD 2B DA 8B D3 FC }

  condition:
    $a0 at pe.entry_point
}