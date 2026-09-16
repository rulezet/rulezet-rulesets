rule TTP_XOR_QUAD_CurrentVersionRun_1f02 {
  strings:
    $key_1f02 = { 4c 6d [2] 68 63 [2] 43 4f [2] 6d 6d [2] 79 76 [2] 76 6c [2] 68 71 [2] 6a 70 [2] 71 76 [2] 6d 71 [2] 71 5e }

  condition:
    any of them
}