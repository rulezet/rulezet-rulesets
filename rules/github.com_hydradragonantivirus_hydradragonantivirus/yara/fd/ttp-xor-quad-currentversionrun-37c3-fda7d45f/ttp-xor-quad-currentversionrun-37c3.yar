rule TTP_XOR_QUAD_CurrentVersionRun_37c3 {
  strings:
    $key_37c3 = { 64 ac [2] 40 a2 [2] 6b 8e [2] 45 ac [2] 51 b7 [2] 5e ad [2] 40 b0 [2] 42 b1 [2] 59 b7 [2] 45 b0 [2] 59 9f }

  condition:
    any of them
}