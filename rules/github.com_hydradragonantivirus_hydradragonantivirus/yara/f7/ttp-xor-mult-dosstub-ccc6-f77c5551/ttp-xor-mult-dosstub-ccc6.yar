rule TTP_XOR_MULT_DOSStub_ccc6 {
  strings:
    $key_ccc6 = { 98 ae [2] ec b6 [2] ab b4 [2] ec a5 [2] a2 a9 [2] ae a3 [2] b9 a8 [2] a2 e6 [2] 9f }

  condition:
    any of them
}