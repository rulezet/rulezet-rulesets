rule TTP_XOR_QUAD_CurrentVersionRun_f4f1 {
  strings:
    $key_f4f1 = { a7 9e [2] 83 90 [2] a8 bc [2] 86 9e [2] 92 85 [2] 9d 9f [2] 83 82 [2] 81 83 [2] 9a 85 [2] 86 82 [2] 9a ad }

  condition:
    any of them
}