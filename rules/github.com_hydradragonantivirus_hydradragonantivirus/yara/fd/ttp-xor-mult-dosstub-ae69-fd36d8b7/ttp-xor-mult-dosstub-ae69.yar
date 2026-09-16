rule TTP_XOR_MULT_DOSStub_ae69 {
  strings:
    $key_ae69 = { fa 01 [2] 8e 19 [2] c9 1b [2] 8e 0a [2] c0 06 [2] cc 0c [2] db 07 [2] c0 49 [2] fd }

  condition:
    any of them
}