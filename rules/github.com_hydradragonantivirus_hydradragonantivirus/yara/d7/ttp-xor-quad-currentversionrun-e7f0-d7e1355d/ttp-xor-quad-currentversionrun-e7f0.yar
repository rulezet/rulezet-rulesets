rule TTP_XOR_QUAD_CurrentVersionRun_e7f0 {
  strings:
    $key_e7f0 = { b4 9f [2] 90 91 [2] bb bd [2] 95 9f [2] 81 84 [2] 8e 9e [2] 90 83 [2] 92 82 [2] 89 84 [2] 95 83 [2] 89 ac }

  condition:
    any of them
}