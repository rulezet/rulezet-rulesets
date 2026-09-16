rule TTP_XOR_MULT_DOSStub_b957 {
  strings:
    $key_b957 = { ed 3f [2] 99 27 [2] de 25 [2] 99 34 [2] d7 38 [2] db 32 [2] cc 39 [2] d7 77 [2] ea }

  condition:
    any of them
}