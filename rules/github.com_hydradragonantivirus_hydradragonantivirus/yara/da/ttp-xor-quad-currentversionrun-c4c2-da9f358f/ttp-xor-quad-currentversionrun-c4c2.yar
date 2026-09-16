rule TTP_XOR_QUAD_CurrentVersionRun_c4c2 {
  strings:
    $key_c4c2 = { 97 ad [2] b3 a3 [2] 98 8f [2] b6 ad [2] a2 b6 [2] ad ac [2] b3 b1 [2] b1 b0 [2] aa b6 [2] b6 b1 [2] aa 9e }

  condition:
    any of them
}