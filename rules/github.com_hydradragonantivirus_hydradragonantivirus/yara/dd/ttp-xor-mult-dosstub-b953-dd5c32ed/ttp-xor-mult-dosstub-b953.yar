rule TTP_XOR_MULT_DOSStub_b953 {
  strings:
    $key_b953 = { ed 3b [2] 99 23 [2] de 21 [2] 99 30 [2] d7 3c [2] db 36 [2] cc 3d [2] d7 73 [2] ea }

  condition:
    any of them
}