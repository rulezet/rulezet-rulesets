rule TTP_XOR_QUAD_CurrentVersionRun_06a8 {
  strings:
    $key_06a8 = { 55 c7 [2] 71 c9 [2] 5a e5 [2] 74 c7 [2] 60 dc [2] 6f c6 [2] 71 db [2] 73 da [2] 68 dc [2] 74 db [2] 68 f4 }

  condition:
    any of them
}