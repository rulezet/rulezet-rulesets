rule TTP_XOR_MULT_DOSStub_7988 {
  strings:
    $key_7988 = { 2d e0 [2] 59 f8 [2] 1e fa [2] 59 eb [2] 17 e7 [2] 1b ed [2] 0c e6 [2] 17 a8 [2] 2a }

  condition:
    any of them
}