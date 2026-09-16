rule TTP_XOR_QUAD_CurrentVersionRun_1213 {
  strings:
    $key_1213 = { 41 7c [2] 65 72 [2] 4e 5e [2] 60 7c [2] 74 67 [2] 7b 7d [2] 65 60 [2] 67 61 [2] 7c 67 [2] 60 60 [2] 7c 4f }

  condition:
    any of them
}