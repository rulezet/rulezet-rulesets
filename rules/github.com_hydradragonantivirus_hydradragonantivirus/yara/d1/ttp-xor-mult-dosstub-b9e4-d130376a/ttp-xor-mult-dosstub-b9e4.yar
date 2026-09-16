rule TTP_XOR_MULT_DOSStub_b9e4 {
  strings:
    $key_b9e4 = { ed 8c [2] 99 94 [2] de 96 [2] 99 87 [2] d7 8b [2] db 81 [2] cc 8a [2] d7 c4 [2] ea }

  condition:
    any of them
}