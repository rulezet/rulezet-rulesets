rule TTP_XOR_QUAD_CurrentVersionRun_d879 {
  strings:
    $key_d879 = { 8b 16 [2] af 18 [2] 84 34 [2] aa 16 [2] be 0d [2] b1 17 [2] af 0a [2] ad 0b [2] b6 0d [2] aa 0a [2] b6 25 }

  condition:
    any of them
}