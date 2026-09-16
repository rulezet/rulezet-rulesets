rule TTP_XOR_MULT_DOSStub_b908 {
  strings:
    $key_b908 = { ed 60 [2] 99 78 [2] de 7a [2] 99 6b [2] d7 67 [2] db 6d [2] cc 66 [2] d7 28 [2] ea }

  condition:
    any of them
}