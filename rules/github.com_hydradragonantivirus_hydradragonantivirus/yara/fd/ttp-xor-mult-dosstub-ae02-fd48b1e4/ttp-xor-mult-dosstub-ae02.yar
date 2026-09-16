rule TTP_XOR_MULT_DOSStub_ae02 {
  strings:
    $key_ae02 = { fa 6a [2] 8e 72 [2] c9 70 [2] 8e 61 [2] c0 6d [2] cc 67 [2] db 6c [2] c0 22 [2] fd }

  condition:
    any of them
}