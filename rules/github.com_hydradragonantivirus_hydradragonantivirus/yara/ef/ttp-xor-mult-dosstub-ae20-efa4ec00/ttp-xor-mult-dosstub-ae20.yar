rule TTP_XOR_MULT_DOSStub_ae20 {
  strings:
    $key_ae20 = { fa 48 [2] 8e 50 [2] c9 52 [2] 8e 43 [2] c0 4f [2] cc 45 [2] db 4e [2] c0 00 [2] fd }

  condition:
    any of them
}