rule TTP_XOR_QUAD_CurrentVersionRun_1d02 {
  strings:
    $key_1d02 = { 4e 6d [2] 6a 63 [2] 41 4f [2] 6f 6d [2] 7b 76 [2] 74 6c [2] 6a 71 [2] 68 70 [2] 73 76 [2] 6f 71 [2] 73 5e }

  condition:
    any of them
}