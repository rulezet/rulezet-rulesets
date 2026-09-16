rule TTP_XOR_QUAD_CurrentVersionRun_17c3 {
  strings:
    $key_17c3 = { 44 ac [2] 60 a2 [2] 4b 8e [2] 65 ac [2] 71 b7 [2] 7e ad [2] 60 b0 [2] 62 b1 [2] 79 b7 [2] 65 b0 [2] 79 9f }

  condition:
    any of them
}