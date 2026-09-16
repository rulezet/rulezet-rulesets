rule TTP_XOR_MULT_DOSStub_ae70 {
  strings:
    $key_ae70 = { fa 18 [2] 8e 00 [2] c9 02 [2] 8e 13 [2] c0 1f [2] cc 15 [2] db 1e [2] c0 50 [2] fd }

  condition:
    any of them
}