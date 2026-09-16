rule TTP_XOR_MULT_DOSStub_ccc5 {
  strings:
    $key_ccc5 = { 98 ad [2] ec b5 [2] ab b7 [2] ec a6 [2] a2 aa [2] ae a0 [2] b9 ab [2] a2 e5 [2] 9f }

  condition:
    any of them
}