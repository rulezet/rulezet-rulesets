rule TTP_XOR_MULT_DOSStub_eac3 {
  strings:
    $key_eac3 = { be ab [2] ca b3 [2] 8d b1 [2] ca a0 [2] 84 ac [2] 88 a6 [2] 9f ad [2] 84 e3 [2] b9 }

  condition:
    any of them
}