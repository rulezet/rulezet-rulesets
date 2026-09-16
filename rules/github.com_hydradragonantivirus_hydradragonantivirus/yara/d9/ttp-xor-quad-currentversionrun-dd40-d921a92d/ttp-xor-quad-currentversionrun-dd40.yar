rule TTP_XOR_QUAD_CurrentVersionRun_dd40 {
  strings:
    $key_dd40 = { 8e 2f [2] aa 21 [2] 81 0d [2] af 2f [2] bb 34 [2] b4 2e [2] aa 33 [2] a8 32 [2] b3 34 [2] af 33 [2] b3 1c }

  condition:
    any of them
}