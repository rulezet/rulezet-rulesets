rule TTP_XOR_QUAD_CurrentVersionRun_f3f1 {
  strings:
    $key_f3f1 = { a0 9e [2] 84 90 [2] af bc [2] 81 9e [2] 95 85 [2] 9a 9f [2] 84 82 [2] 86 83 [2] 9d 85 [2] 81 82 [2] 9d ad }

  condition:
    any of them
}