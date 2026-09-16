rule TTP_XOR_QUAD_CurrentVersionRun_76ec {
  strings:
    $key_76ec = { 25 83 [2] 01 8d [2] 2a a1 [2] 04 83 [2] 10 98 [2] 1f 82 [2] 01 9f [2] 03 9e [2] 18 98 [2] 04 9f [2] 18 b0 }

  condition:
    any of them
}