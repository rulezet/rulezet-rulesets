rule TTP_XOR_QUAD_CurrentVersionRun_0c02 {
  strings:
    $key_0c02 = { 5f 6d [2] 7b 63 [2] 50 4f [2] 7e 6d [2] 6a 76 [2] 65 6c [2] 7b 71 [2] 79 70 [2] 62 76 [2] 7e 71 [2] 62 5e }

  condition:
    any of them
}