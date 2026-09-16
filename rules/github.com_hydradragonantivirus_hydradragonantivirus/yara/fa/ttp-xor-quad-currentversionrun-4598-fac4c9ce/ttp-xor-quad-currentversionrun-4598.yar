rule TTP_XOR_QUAD_CurrentVersionRun_4598 {
  strings:
    $key_4598 = { 16 f7 [2] 32 f9 [2] 19 d5 [2] 37 f7 [2] 23 ec [2] 2c f6 [2] 32 eb [2] 30 ea [2] 2b ec [2] 37 eb [2] 2b c4 }

  condition:
    any of them
}