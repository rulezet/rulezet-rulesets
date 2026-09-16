rule TTP_XOR_QUAD_CurrentVersionRun_1312 {
  strings:
    $key_1312 = { 40 7d [2] 64 73 [2] 4f 5f [2] 61 7d [2] 75 66 [2] 7a 7c [2] 64 61 [2] 66 60 [2] 7d 66 [2] 61 61 [2] 7d 4e }

  condition:
    any of them
}