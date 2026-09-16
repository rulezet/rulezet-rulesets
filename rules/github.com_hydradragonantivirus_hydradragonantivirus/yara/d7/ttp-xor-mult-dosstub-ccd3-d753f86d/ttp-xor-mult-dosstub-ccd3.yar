rule TTP_XOR_MULT_DOSStub_ccd3 {
  strings:
    $key_ccd3 = { 98 bb [2] ec a3 [2] ab a1 [2] ec b0 [2] a2 bc [2] ae b6 [2] b9 bd [2] a2 f3 [2] 9f }

  condition:
    any of them
}