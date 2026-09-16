rule TTP_XOR_QUAD_CurrentVersionRun_37c2 {
  strings:
    $key_37c2 = { 64 ad [2] 40 a3 [2] 6b 8f [2] 45 ad [2] 51 b6 [2] 5e ac [2] 40 b1 [2] 42 b0 [2] 59 b6 [2] 45 b1 [2] 59 9e }

  condition:
    any of them
}