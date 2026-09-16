rule TTP_XOR_QUAD_CurrentVersionRun_d877 {
  strings:
    $key_d877 = { 8b 18 [2] af 16 [2] 84 3a [2] aa 18 [2] be 03 [2] b1 19 [2] af 04 [2] ad 05 [2] b6 03 [2] aa 04 [2] b6 2b }

  condition:
    any of them
}