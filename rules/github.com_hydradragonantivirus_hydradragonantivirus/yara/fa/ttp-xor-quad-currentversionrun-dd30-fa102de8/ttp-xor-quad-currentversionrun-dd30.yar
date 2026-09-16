rule TTP_XOR_QUAD_CurrentVersionRun_dd30 {
  strings:
    $key_dd30 = { 8e 5f [2] aa 51 [2] 81 7d [2] af 5f [2] bb 44 [2] b4 5e [2] aa 43 [2] a8 42 [2] b3 44 [2] af 43 [2] b3 6c }

  condition:
    any of them
}