rule TTP_XOR_MULT_DOSStub_b93a {
  strings:
    $key_b93a = { ed 52 [2] 99 4a [2] de 48 [2] 99 59 [2] d7 55 [2] db 5f [2] cc 54 [2] d7 1a [2] ea }

  condition:
    any of them
}