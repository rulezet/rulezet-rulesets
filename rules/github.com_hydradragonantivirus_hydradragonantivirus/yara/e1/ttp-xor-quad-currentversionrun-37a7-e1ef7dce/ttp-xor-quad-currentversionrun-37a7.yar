rule TTP_XOR_QUAD_CurrentVersionRun_37a7 {
  strings:
    $key_37a7 = { 64 c8 [2] 40 c6 [2] 6b ea [2] 45 c8 [2] 51 d3 [2] 5e c9 [2] 40 d4 [2] 42 d5 [2] 59 d3 [2] 45 d4 [2] 59 fb }

  condition:
    any of them
}