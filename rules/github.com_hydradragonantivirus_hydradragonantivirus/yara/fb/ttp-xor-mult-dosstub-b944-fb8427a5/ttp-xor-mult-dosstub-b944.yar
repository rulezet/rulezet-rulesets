rule TTP_XOR_MULT_DOSStub_b944 {
  strings:
    $key_b944 = { ed 2c [2] 99 34 [2] de 36 [2] 99 27 [2] d7 2b [2] db 21 [2] cc 2a [2] d7 64 [2] ea }

  condition:
    any of them
}