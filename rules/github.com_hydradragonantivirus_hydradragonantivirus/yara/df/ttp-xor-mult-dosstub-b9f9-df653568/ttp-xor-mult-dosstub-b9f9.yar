rule TTP_XOR_MULT_DOSStub_b9f9 {
  strings:
    $key_b9f9 = { ed 91 [2] 99 89 [2] de 8b [2] 99 9a [2] d7 96 [2] db 9c [2] cc 97 [2] d7 d9 [2] ea }

  condition:
    any of them
}