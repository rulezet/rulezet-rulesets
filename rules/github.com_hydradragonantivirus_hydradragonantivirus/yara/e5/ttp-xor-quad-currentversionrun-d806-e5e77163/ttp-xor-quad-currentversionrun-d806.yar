rule TTP_XOR_QUAD_CurrentVersionRun_d806 {
  strings:
    $key_d806 = { 8b 69 [2] af 67 [2] 84 4b [2] aa 69 [2] be 72 [2] b1 68 [2] af 75 [2] ad 74 [2] b6 72 [2] aa 75 [2] b6 5a }

  condition:
    any of them
}