rule TTP_XOR_MULT_DOSStub_b904 {
  strings:
    $key_b904 = { ed 6c [2] 99 74 [2] de 76 [2] 99 67 [2] d7 6b [2] db 61 [2] cc 6a [2] d7 24 [2] ea }

  condition:
    any of them
}