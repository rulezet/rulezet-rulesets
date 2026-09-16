rule TTP_XOR_MULT_DOSStub_b948 {
  strings:
    $key_b948 = { ed 20 [2] 99 38 [2] de 3a [2] 99 2b [2] d7 27 [2] db 2d [2] cc 26 [2] d7 68 [2] ea }

  condition:
    any of them
}