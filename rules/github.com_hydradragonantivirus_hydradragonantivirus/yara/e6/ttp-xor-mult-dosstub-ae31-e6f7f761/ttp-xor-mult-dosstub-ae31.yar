rule TTP_XOR_MULT_DOSStub_ae31 {
  strings:
    $key_ae31 = { fa 59 [2] 8e 41 [2] c9 43 [2] 8e 52 [2] c0 5e [2] cc 54 [2] db 5f [2] c0 11 [2] fd }

  condition:
    any of them
}