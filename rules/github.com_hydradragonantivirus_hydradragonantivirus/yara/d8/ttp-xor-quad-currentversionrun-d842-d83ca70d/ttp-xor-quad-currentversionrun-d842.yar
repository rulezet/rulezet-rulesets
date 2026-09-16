rule TTP_XOR_QUAD_CurrentVersionRun_d842 {
  strings:
    $key_d842 = { 8b 2d [2] af 23 [2] 84 0f [2] aa 2d [2] be 36 [2] b1 2c [2] af 31 [2] ad 30 [2] b6 36 [2] aa 31 [2] b6 1e }

  condition:
    any of them
}