rule TTP_XOR_MULT_DOSStub_ae36 {
  strings:
    $key_ae36 = { fa 5e [2] 8e 46 [2] c9 44 [2] 8e 55 [2] c0 59 [2] cc 53 [2] db 58 [2] c0 16 [2] fd }

  condition:
    any of them
}