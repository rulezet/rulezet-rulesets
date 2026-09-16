rule TTP_XOR_MULT_DOSStub_ae0b {
  strings:
    $key_ae0b = { fa 63 [2] 8e 7b [2] c9 79 [2] 8e 68 [2] c0 64 [2] cc 6e [2] db 65 [2] c0 2b [2] fd }

  condition:
    any of them
}