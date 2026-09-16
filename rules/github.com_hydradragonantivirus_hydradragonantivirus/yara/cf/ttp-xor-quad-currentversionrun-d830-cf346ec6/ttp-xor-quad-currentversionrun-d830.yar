rule TTP_XOR_QUAD_CurrentVersionRun_d830 {
  strings:
    $key_d830 = { 8b 5f [2] af 51 [2] 84 7d [2] aa 5f [2] be 44 [2] b1 5e [2] af 43 [2] ad 42 [2] b6 44 [2] aa 43 [2] b6 6c }

  condition:
    any of them
}