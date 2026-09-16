rule TTP_XOR_MULT_DOSStub_8ac3 {
  strings:
    $key_8ac3 = { de ab [2] aa b3 [2] ed b1 [2] aa a0 [2] e4 ac [2] e8 a6 [2] ff ad [2] e4 e3 [2] d9 }

  condition:
    any of them
}