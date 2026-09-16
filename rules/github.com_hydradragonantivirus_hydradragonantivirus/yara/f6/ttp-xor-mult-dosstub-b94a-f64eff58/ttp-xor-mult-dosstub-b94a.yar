rule TTP_XOR_MULT_DOSStub_b94a {
  strings:
    $key_b94a = { ed 22 [2] 99 3a [2] de 38 [2] 99 29 [2] d7 25 [2] db 2f [2] cc 24 [2] d7 6a [2] ea }

  condition:
    any of them
}