rule TTP_XOR_QUAD_CurrentVersionRun_66a3 {
  strings:
    $key_66a3 = { 35 cc [2] 11 c2 [2] 3a ee [2] 14 cc [2] 00 d7 [2] 0f cd [2] 11 d0 [2] 13 d1 [2] 08 d7 [2] 14 d0 [2] 08 ff }

  condition:
    any of them
}