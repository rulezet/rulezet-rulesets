rule TTP_XOR_QUAD_CurrentVersionRun_14c2 {
  strings:
    $key_14c2 = { 47 ad [2] 63 a3 [2] 48 8f [2] 66 ad [2] 72 b6 [2] 7d ac [2] 63 b1 [2] 61 b0 [2] 7a b6 [2] 66 b1 [2] 7a 9e }

  condition:
    any of them
}