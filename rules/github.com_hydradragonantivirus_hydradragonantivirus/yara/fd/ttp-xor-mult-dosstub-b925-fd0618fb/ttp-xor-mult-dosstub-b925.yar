rule TTP_XOR_MULT_DOSStub_b925 {
  strings:
    $key_b925 = { ed 4d [2] 99 55 [2] de 57 [2] 99 46 [2] d7 4a [2] db 40 [2] cc 4b [2] d7 05 [2] ea }

  condition:
    any of them
}