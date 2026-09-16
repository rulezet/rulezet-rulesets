rule PEiD_03482_WWPACK_v3_02__v3_02a__v3_04__Relocations_pack__ {
  meta:
    description = "[WWPACK v3.02, v3.02a, v3.04 (Relocations pack)]"
    ep_only     = "true"

  strings:
    $a = { BE ?? ?? BF ?? ?? B9 ?? ?? 8C CD 81 ED ?? ?? 8B DD 81 EB ?? ?? 8B D3 FC FA 1E 8E DB 01 15 33 C0 2E AC }

  condition:
    $a
}