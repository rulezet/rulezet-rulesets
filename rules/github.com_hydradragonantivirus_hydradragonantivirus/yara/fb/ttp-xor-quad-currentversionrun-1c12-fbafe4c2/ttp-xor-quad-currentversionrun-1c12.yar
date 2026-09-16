rule TTP_XOR_QUAD_CurrentVersionRun_1c12 {
  strings:
    $key_1c12 = { 4f 7d [2] 6b 73 [2] 40 5f [2] 6e 7d [2] 7a 66 [2] 75 7c [2] 6b 61 [2] 69 60 [2] 72 66 [2] 6e 61 [2] 72 4e }

  condition:
    any of them
}