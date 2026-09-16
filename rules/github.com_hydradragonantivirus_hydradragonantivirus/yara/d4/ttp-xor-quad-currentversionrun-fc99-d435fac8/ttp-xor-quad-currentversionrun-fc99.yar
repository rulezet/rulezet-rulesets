rule TTP_XOR_QUAD_CurrentVersionRun_fc99 {
  strings:
    $key_fc99 = { af f6 [2] 8b f8 [2] a0 d4 [2] 8e f6 [2] 9a ed [2] 95 f7 [2] 8b ea [2] 89 eb [2] 92 ed [2] 8e ea [2] 92 c5 }

  condition:
    any of them
}