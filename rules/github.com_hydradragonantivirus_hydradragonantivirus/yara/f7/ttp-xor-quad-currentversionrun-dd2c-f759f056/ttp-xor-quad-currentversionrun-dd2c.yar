rule TTP_XOR_QUAD_CurrentVersionRun_dd2c {
  strings:
    $key_dd2c = { 8e 43 [2] aa 4d [2] 81 61 [2] af 43 [2] bb 58 [2] b4 42 [2] aa 5f [2] a8 5e [2] b3 58 [2] af 5f [2] b3 70 }

  condition:
    any of them
}