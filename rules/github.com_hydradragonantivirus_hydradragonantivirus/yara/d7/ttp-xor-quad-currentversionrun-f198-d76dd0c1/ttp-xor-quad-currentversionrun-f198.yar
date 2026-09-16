rule TTP_XOR_QUAD_CurrentVersionRun_f198 {
  strings:
    $key_f198 = { a2 f7 [2] 86 f9 [2] ad d5 [2] 83 f7 [2] 97 ec [2] 98 f6 [2] 86 eb [2] 84 ea [2] 9f ec [2] 83 eb [2] 9f c4 }

  condition:
    any of them
}