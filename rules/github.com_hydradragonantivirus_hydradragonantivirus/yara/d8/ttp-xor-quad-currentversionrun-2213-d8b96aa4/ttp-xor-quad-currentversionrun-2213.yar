rule TTP_XOR_QUAD_CurrentVersionRun_2213 {
  strings:
    $key_2213 = { 71 7c [2] 55 72 [2] 7e 5e [2] 50 7c [2] 44 67 [2] 4b 7d [2] 55 60 [2] 57 61 [2] 4c 67 [2] 50 60 [2] 4c 4f }

  condition:
    any of them
}