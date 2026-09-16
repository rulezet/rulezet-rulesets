rule TTP_XOR_MULT_DOSStub_8ed3 {
  strings:
    $key_8ed3 = { da bb [2] ae a3 [2] e9 a1 [2] ae b0 [2] e0 bc [2] ec b6 [2] fb bd [2] e0 f3 [2] dd }

  condition:
    any of them
}