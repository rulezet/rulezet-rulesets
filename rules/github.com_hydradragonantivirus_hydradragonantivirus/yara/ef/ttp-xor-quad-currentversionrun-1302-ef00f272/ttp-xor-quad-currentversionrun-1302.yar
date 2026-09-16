rule TTP_XOR_QUAD_CurrentVersionRun_1302 {
  strings:
    $key_1302 = { 40 6d [2] 64 63 [2] 4f 4f [2] 61 6d [2] 75 76 [2] 7a 6c [2] 64 71 [2] 66 70 [2] 7d 76 [2] 61 71 [2] 7d 5e }

  condition:
    any of them
}