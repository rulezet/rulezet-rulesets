rule TTP_XOR_QUAD_CurrentVersionRun_3302 {
  strings:
    $key_3302 = { 60 6d [2] 44 63 [2] 6f 4f [2] 41 6d [2] 55 76 [2] 5a 6c [2] 44 71 [2] 46 70 [2] 5d 76 [2] 41 71 [2] 5d 5e }

  condition:
    any of them
}