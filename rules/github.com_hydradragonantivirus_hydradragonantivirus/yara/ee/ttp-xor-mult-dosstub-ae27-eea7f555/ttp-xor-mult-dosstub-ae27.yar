rule TTP_XOR_MULT_DOSStub_ae27 {
  strings:
    $key_ae27 = { fa 4f [2] 8e 57 [2] c9 55 [2] 8e 44 [2] c0 48 [2] cc 42 [2] db 49 [2] c0 07 [2] fd }

  condition:
    any of them
}