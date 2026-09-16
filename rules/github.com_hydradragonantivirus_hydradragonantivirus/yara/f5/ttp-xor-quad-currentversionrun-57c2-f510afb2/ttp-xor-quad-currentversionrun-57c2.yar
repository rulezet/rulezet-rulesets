rule TTP_XOR_QUAD_CurrentVersionRun_57c2 {
  strings:
    $key_57c2 = { 04 ad [2] 20 a3 [2] 0b 8f [2] 25 ad [2] 31 b6 [2] 3e ac [2] 20 b1 [2] 22 b0 [2] 39 b6 [2] 25 b1 [2] 39 9e }

  condition:
    any of them
}