rule TTP_XOR_MULT_DOSStub_b916 {
  strings:
    $key_b916 = { ed 7e [2] 99 66 [2] de 64 [2] 99 75 [2] d7 79 [2] db 73 [2] cc 78 [2] d7 36 [2] ea }

  condition:
    any of them
}