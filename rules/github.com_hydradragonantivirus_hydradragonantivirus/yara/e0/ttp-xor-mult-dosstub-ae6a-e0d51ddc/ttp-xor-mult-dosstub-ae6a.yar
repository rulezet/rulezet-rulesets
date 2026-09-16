rule TTP_XOR_MULT_DOSStub_ae6a {
  strings:
    $key_ae6a = { fa 02 [2] 8e 1a [2] c9 18 [2] 8e 09 [2] c0 05 [2] cc 0f [2] db 04 [2] c0 4a [2] fd }

  condition:
    any of them
}