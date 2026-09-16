rule TTP_XOR_MULT_DOSStub_adc4 {
  strings:
    $key_adc4 = { f9 ac [2] 8d b4 [2] ca b6 [2] 8d a7 [2] c3 ab [2] cf a1 [2] d8 aa [2] c3 e4 [2] fe }

  condition:
    any of them
}