rule TTP_XOR_MULT_DOSStub_b905 {
  strings:
    $key_b905 = { ed 6d [2] 99 75 [2] de 77 [2] 99 66 [2] d7 6a [2] db 60 [2] cc 6b [2] d7 25 [2] ea }

  condition:
    any of them
}