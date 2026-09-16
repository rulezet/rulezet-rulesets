rule TTP_XOR_QUAD_CurrentVersionRun_1812 {
  strings:
    $key_1812 = { 4b 7d [2] 6f 73 [2] 44 5f [2] 6a 7d [2] 7e 66 [2] 71 7c [2] 6f 61 [2] 6d 60 [2] 76 66 [2] 6a 61 [2] 76 4e }

  condition:
    any of them
}