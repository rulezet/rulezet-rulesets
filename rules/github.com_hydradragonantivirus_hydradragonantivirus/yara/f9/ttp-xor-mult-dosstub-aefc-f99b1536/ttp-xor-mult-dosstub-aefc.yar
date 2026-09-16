rule TTP_XOR_MULT_DOSStub_aefc {
  strings:
    $key_aefc = { fa 94 [2] 8e 8c [2] c9 8e [2] 8e 9f [2] c0 93 [2] cc 99 [2] db 92 [2] c0 dc [2] fd }

  condition:
    any of them
}