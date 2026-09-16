rule TTP_XOR_QUAD_CurrentVersionRun_d873 {
  strings:
    $key_d873 = { 8b 1c [2] af 12 [2] 84 3e [2] aa 1c [2] be 07 [2] b1 1d [2] af 00 [2] ad 01 [2] b6 07 [2] aa 00 [2] b6 2f }

  condition:
    any of them
}