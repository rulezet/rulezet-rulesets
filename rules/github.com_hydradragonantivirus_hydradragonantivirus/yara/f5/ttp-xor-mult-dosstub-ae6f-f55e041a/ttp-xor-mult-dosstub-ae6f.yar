rule TTP_XOR_MULT_DOSStub_ae6f {
  strings:
    $key_ae6f = { fa 07 [2] 8e 1f [2] c9 1d [2] 8e 0c [2] c0 00 [2] cc 0a [2] db 01 [2] c0 4f [2] fd }

  condition:
    any of them
}