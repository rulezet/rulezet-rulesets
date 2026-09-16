rule TTP_XOR_QUAD_CurrentVersionRun_d85c {
  strings:
    $key_d85c = { 8b 33 [2] af 3d [2] 84 11 [2] aa 33 [2] be 28 [2] b1 32 [2] af 2f [2] ad 2e [2] b6 28 [2] aa 2f [2] b6 00 }

  condition:
    any of them
}