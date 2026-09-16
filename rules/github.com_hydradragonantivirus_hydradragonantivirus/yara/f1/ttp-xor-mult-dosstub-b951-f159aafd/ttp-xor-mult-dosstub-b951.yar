rule TTP_XOR_MULT_DOSStub_b951 {
  strings:
    $key_b951 = { ed 39 [2] 99 21 [2] de 23 [2] 99 32 [2] d7 3e [2] db 34 [2] cc 3f [2] d7 71 [2] ea }

  condition:
    any of them
}