rule TTP_XOR_QUAD_CurrentVersionRun_aab3 {
  strings:
    $key_aab3 = { f9 dc [2] dd d2 [2] f6 fe [2] d8 dc [2] cc c7 [2] c3 dd [2] dd c0 [2] df c1 [2] c4 c7 [2] d8 c0 [2] c4 ef }

  condition:
    any of them
}