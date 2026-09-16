rule TTP_XOR_MULT_DOSStub_ccc0 {
  strings:
    $key_ccc0 = { 98 a8 [2] ec b0 [2] ab b2 [2] ec a3 [2] a2 af [2] ae a5 [2] b9 ae [2] a2 e0 [2] 9f }

  condition:
    any of them
}