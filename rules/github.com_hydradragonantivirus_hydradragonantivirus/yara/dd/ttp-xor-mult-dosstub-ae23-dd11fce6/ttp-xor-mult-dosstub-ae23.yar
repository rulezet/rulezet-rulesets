rule TTP_XOR_MULT_DOSStub_ae23 {
  strings:
    $key_ae23 = { fa 4b [2] 8e 53 [2] c9 51 [2] 8e 40 [2] c0 4c [2] cc 46 [2] db 4d [2] c0 03 [2] fd }

  condition:
    any of them
}