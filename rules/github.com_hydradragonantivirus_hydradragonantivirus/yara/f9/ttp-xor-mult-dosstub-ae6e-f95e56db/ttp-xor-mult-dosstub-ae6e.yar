rule TTP_XOR_MULT_DOSStub_ae6e {
  strings:
    $key_ae6e = { fa 06 [2] 8e 1e [2] c9 1c [2] 8e 0d [2] c0 01 [2] cc 0b [2] db 00 [2] c0 4e [2] fd }

  condition:
    any of them
}