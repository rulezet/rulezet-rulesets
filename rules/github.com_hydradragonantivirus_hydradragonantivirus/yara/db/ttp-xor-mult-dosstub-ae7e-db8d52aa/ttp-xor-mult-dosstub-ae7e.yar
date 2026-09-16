rule TTP_XOR_MULT_DOSStub_ae7e {
  strings:
    $key_ae7e = { fa 16 [2] 8e 0e [2] c9 0c [2] 8e 1d [2] c0 11 [2] cc 1b [2] db 10 [2] c0 5e [2] fd }

  condition:
    any of them
}