rule TTP_XOR_MULT_DOSStub_ae46 {
  strings:
    $key_ae46 = { fa 2e [2] 8e 36 [2] c9 34 [2] 8e 25 [2] c0 29 [2] cc 23 [2] db 28 [2] c0 66 [2] fd }

  condition:
    any of them
}