rule TTP_XOR_MULT_DOSStub_ae7c {
  strings:
    $key_ae7c = { fa 14 [2] 8e 0c [2] c9 0e [2] 8e 1f [2] c0 13 [2] cc 19 [2] db 12 [2] c0 5c [2] fd }

  condition:
    any of them
}