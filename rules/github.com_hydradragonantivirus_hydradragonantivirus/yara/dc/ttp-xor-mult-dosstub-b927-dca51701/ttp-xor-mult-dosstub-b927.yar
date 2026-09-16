rule TTP_XOR_MULT_DOSStub_b927 {
  strings:
    $key_b927 = { ed 4f [2] 99 57 [2] de 55 [2] 99 44 [2] d7 48 [2] db 42 [2] cc 49 [2] d7 07 [2] ea }

  condition:
    any of them
}