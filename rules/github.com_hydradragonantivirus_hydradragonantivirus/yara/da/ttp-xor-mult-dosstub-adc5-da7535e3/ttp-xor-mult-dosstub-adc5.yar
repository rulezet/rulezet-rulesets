rule TTP_XOR_MULT_DOSStub_adc5 {
  strings:
    $key_adc5 = { f9 ad [2] 8d b5 [2] ca b7 [2] 8d a6 [2] c3 aa [2] cf a0 [2] d8 ab [2] c3 e5 [2] fe }

  condition:
    any of them
}