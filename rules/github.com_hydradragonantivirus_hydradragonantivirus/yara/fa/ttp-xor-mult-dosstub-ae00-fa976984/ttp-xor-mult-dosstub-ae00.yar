rule TTP_XOR_MULT_DOSStub_ae00 {
  strings:
    $key_ae00 = { fa 68 [2] 8e 70 [2] c9 72 [2] 8e 63 [2] c0 6f [2] cc 65 [2] db 6e [2] c0 20 [2] fd }

  condition:
    any of them
}