rule TTP_XOR_MULT_DOSStub_ae2f {
  strings:
    $key_ae2f = { fa 47 [2] 8e 5f [2] c9 5d [2] 8e 4c [2] c0 40 [2] cc 4a [2] db 41 [2] c0 0f [2] fd }

  condition:
    any of them
}