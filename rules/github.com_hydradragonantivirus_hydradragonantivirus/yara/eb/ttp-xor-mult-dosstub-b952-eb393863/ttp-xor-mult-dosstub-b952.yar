rule TTP_XOR_MULT_DOSStub_b952 {
  strings:
    $key_b952 = { ed 3a [2] 99 22 [2] de 20 [2] 99 31 [2] d7 3d [2] db 37 [2] cc 3c [2] d7 72 [2] ea }

  condition:
    any of them
}