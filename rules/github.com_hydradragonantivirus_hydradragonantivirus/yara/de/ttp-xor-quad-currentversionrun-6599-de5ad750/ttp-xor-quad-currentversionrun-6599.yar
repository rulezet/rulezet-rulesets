rule TTP_XOR_QUAD_CurrentVersionRun_6599 {
  strings:
    $key_6599 = { 36 f6 [2] 12 f8 [2] 39 d4 [2] 17 f6 [2] 03 ed [2] 0c f7 [2] 12 ea [2] 10 eb [2] 0b ed [2] 17 ea [2] 0b c5 }

  condition:
    any of them
}