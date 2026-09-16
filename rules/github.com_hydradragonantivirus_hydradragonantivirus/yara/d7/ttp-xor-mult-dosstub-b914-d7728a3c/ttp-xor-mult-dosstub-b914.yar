rule TTP_XOR_MULT_DOSStub_b914 {
  strings:
    $key_b914 = { ed 7c [2] 99 64 [2] de 66 [2] 99 77 [2] d7 7b [2] db 71 [2] cc 7a [2] d7 34 [2] ea }

  condition:
    any of them
}