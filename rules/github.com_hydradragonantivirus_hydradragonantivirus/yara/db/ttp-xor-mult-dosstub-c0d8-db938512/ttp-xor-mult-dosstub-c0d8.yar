rule TTP_XOR_MULT_DOSStub_c0d8 {
  strings:
    $key_c0d8 = { 94 b0 [2] e0 a8 [2] a7 aa [2] e0 bb [2] ae b7 [2] a2 bd [2] b5 b6 [2] ae f8 [2] 93 }

  condition:
    any of them
}