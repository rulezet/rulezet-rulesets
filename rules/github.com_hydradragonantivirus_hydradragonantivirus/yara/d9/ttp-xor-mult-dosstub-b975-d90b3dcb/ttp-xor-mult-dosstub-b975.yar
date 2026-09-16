rule TTP_XOR_MULT_DOSStub_b975 {
  strings:
    $key_b975 = { ed 1d [2] 99 05 [2] de 07 [2] 99 16 [2] d7 1a [2] db 10 [2] cc 1b [2] d7 55 [2] ea }

  condition:
    any of them
}