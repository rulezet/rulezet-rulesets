rule TTP_XOR_MULT_DOSStub_b91a {
  strings:
    $key_b91a = { ed 72 [2] 99 6a [2] de 68 [2] 99 79 [2] d7 75 [2] db 7f [2] cc 74 [2] d7 3a [2] ea }

  condition:
    any of them
}