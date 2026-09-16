rule TTP_XOR_MULT_DOSStub_b92d {
  strings:
    $key_b92d = { ed 45 [2] 99 5d [2] de 5f [2] 99 4e [2] d7 42 [2] db 48 [2] cc 43 [2] d7 0d [2] ea }

  condition:
    any of them
}