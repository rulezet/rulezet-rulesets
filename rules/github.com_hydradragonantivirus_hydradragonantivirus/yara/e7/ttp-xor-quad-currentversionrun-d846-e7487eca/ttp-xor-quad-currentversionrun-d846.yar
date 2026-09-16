rule TTP_XOR_QUAD_CurrentVersionRun_d846 {
  strings:
    $key_d846 = { 8b 29 [2] af 27 [2] 84 0b [2] aa 29 [2] be 32 [2] b1 28 [2] af 35 [2] ad 34 [2] b6 32 [2] aa 35 [2] b6 1a }

  condition:
    any of them
}