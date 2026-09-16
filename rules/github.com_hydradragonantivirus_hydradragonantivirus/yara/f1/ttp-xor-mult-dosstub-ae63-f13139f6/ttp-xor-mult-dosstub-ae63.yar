rule TTP_XOR_MULT_DOSStub_ae63 {
  strings:
    $key_ae63 = { fa 0b [2] 8e 13 [2] c9 11 [2] 8e 00 [2] c0 0c [2] cc 06 [2] db 0d [2] c0 43 [2] fd }

  condition:
    any of them
}