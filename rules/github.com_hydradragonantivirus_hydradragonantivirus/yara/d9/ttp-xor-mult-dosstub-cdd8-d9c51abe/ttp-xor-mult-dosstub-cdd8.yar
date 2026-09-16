rule TTP_XOR_MULT_DOSStub_cdd8 {
  strings:
    $key_cdd8 = { 99 b0 [2] ed a8 [2] aa aa [2] ed bb [2] a3 b7 [2] af bd [2] b8 b6 [2] a3 f8 [2] 9e }

  condition:
    any of them
}