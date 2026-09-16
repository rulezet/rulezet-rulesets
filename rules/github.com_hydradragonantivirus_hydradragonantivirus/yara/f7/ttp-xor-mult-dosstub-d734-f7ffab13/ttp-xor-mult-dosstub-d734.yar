rule TTP_XOR_MULT_DOSStub_d734 {
  strings:
    $key_d734 = { 83 5c [2] f7 44 [2] b0 46 [2] f7 57 [2] b9 5b [2] b5 51 [2] a2 5a [2] b9 14 [2] 84 }

  condition:
    any of them
}