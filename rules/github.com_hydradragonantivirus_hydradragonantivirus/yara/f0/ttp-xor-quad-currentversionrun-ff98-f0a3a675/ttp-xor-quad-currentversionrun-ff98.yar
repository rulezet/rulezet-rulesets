rule TTP_XOR_QUAD_CurrentVersionRun_ff98 {
  strings:
    $key_ff98 = { ac f7 [2] 88 f9 [2] a3 d5 [2] 8d f7 [2] 99 ec [2] 96 f6 [2] 88 eb [2] 8a ea [2] 91 ec [2] 8d eb [2] 91 c4 }

  condition:
    any of them
}