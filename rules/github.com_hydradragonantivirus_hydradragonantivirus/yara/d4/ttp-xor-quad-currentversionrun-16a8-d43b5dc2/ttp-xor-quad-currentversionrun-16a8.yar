rule TTP_XOR_QUAD_CurrentVersionRun_16a8 {
  strings:
    $key_16a8 = { 45 c7 [2] 61 c9 [2] 4a e5 [2] 64 c7 [2] 70 dc [2] 7f c6 [2] 61 db [2] 63 da [2] 78 dc [2] 64 db [2] 78 f4 }

  condition:
    any of them
}