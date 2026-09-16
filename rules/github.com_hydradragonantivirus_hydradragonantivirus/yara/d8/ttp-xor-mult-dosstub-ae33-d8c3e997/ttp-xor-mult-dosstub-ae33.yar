rule TTP_XOR_MULT_DOSStub_ae33 {
  strings:
    $key_ae33 = { fa 5b [2] 8e 43 [2] c9 41 [2] 8e 50 [2] c0 5c [2] cc 56 [2] db 5d [2] c0 13 [2] fd }

  condition:
    any of them
}