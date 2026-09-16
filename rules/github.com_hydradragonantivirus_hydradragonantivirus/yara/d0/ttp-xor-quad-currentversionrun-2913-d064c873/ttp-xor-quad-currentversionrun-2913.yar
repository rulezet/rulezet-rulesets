rule TTP_XOR_QUAD_CurrentVersionRun_2913 {
  strings:
    $key_2913 = { 7a 7c [2] 5e 72 [2] 75 5e [2] 5b 7c [2] 4f 67 [2] 40 7d [2] 5e 60 [2] 5c 61 [2] 47 67 [2] 5b 60 [2] 47 4f }

  condition:
    any of them
}