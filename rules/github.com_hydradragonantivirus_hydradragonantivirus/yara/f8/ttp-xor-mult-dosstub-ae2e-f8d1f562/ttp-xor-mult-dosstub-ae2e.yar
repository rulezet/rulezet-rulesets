rule TTP_XOR_MULT_DOSStub_ae2e {
  strings:
    $key_ae2e = { fa 46 [2] 8e 5e [2] c9 5c [2] 8e 4d [2] c0 41 [2] cc 4b [2] db 40 [2] c0 0e [2] fd }

  condition:
    any of them
}