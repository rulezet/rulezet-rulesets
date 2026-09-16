rule TTP_XOR_MULT_DOSStub_ae9b {
  strings:
    $key_ae9b = { fa f3 [2] 8e eb [2] c9 e9 [2] 8e f8 [2] c0 f4 [2] cc fe [2] db f5 [2] c0 bb [2] fd }

  condition:
    any of them
}