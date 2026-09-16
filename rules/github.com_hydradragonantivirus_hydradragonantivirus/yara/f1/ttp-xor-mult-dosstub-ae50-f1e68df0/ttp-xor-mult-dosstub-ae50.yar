rule TTP_XOR_MULT_DOSStub_ae50 {
  strings:
    $key_ae50 = { fa 38 [2] 8e 20 [2] c9 22 [2] 8e 33 [2] c0 3f [2] cc 35 [2] db 3e [2] c0 70 [2] fd }

  condition:
    any of them
}