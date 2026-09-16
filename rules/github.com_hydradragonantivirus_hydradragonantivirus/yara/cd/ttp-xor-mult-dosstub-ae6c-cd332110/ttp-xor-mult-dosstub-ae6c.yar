rule TTP_XOR_MULT_DOSStub_ae6c {
  strings:
    $key_ae6c = { fa 04 [2] 8e 1c [2] c9 1e [2] 8e 0f [2] c0 03 [2] cc 09 [2] db 02 [2] c0 4c [2] fd }

  condition:
    any of them
}