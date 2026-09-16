rule TTP_XOR_QUAD_CurrentVersionRun_d85a {
  strings:
    $key_d85a = { 8b 35 [2] af 3b [2] 84 17 [2] aa 35 [2] be 2e [2] b1 34 [2] af 29 [2] ad 28 [2] b6 2e [2] aa 29 [2] b6 06 }

  condition:
    any of them
}