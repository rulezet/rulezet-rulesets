rule TTP_XOR_QUAD_CurrentVersionRun_4c02 {
  strings:
    $key_4c02 = { 1f 6d [2] 3b 63 [2] 10 4f [2] 3e 6d [2] 2a 76 [2] 25 6c [2] 3b 71 [2] 39 70 [2] 22 76 [2] 3e 71 [2] 22 5e }

  condition:
    any of them
}