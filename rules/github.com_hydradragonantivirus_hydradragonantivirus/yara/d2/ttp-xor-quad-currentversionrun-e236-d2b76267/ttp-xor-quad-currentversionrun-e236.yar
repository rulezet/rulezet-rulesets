rule TTP_XOR_QUAD_CurrentVersionRun_e236 {
  strings:
    $key_e236 = { b1 59 [2] 95 57 [2] be 7b [2] 90 59 [2] 84 42 [2] 8b 58 [2] 95 45 [2] 97 44 [2] 8c 42 [2] 90 45 [2] 8c 6a }

  condition:
    any of them
}