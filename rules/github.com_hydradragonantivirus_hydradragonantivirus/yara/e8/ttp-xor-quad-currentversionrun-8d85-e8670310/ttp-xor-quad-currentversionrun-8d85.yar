rule TTP_XOR_QUAD_CurrentVersionRun_8d85 {
  strings:
    $key_8d85 = { de ea [2] fa e4 [2] d1 c8 [2] ff ea [2] eb f1 [2] e4 eb [2] fa f6 [2] f8 f7 [2] e3 f1 [2] ff f6 [2] e3 d9 }

  condition:
    any of them
}