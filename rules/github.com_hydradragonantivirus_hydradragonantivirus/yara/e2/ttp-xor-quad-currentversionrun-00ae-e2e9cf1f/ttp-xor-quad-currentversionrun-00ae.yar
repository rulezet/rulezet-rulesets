rule TTP_XOR_QUAD_CurrentVersionRun_00ae {
  strings:
    $key_00ae = { 53 c1 [2] 77 cf [2] 5c e3 [2] 72 c1 [2] 66 da [2] 69 c0 [2] 77 dd [2] 75 dc [2] 6e da [2] 72 dd [2] 6e f2 }

  condition:
    any of them
}