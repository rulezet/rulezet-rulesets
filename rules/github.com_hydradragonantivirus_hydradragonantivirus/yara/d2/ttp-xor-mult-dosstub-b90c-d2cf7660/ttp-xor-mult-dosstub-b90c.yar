rule TTP_XOR_MULT_DOSStub_b90c {
  strings:
    $key_b90c = { ed 64 [2] 99 7c [2] de 7e [2] 99 6f [2] d7 63 [2] db 69 [2] cc 62 [2] d7 2c [2] ea }

  condition:
    any of them
}