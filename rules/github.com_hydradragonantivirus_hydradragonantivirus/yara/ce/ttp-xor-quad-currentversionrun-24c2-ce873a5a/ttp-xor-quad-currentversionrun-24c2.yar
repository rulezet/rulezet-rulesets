rule TTP_XOR_QUAD_CurrentVersionRun_24c2 {
  strings:
    $key_24c2 = { 77 ad [2] 53 a3 [2] 78 8f [2] 56 ad [2] 42 b6 [2] 4d ac [2] 53 b1 [2] 51 b0 [2] 4a b6 [2] 56 b1 [2] 4a 9e }

  condition:
    any of them
}