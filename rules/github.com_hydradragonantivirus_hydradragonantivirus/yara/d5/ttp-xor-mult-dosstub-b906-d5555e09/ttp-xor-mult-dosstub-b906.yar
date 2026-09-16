rule TTP_XOR_MULT_DOSStub_b906 {
  strings:
    $key_b906 = { ed 6e [2] 99 76 [2] de 74 [2] 99 65 [2] d7 69 [2] db 63 [2] cc 68 [2] d7 26 [2] ea }

  condition:
    any of them
}