rule TTP_XOR_MULT_DOSStub_d634 {
  strings:
    $key_d634 = { 82 5c [2] f6 44 [2] b1 46 [2] f6 57 [2] b8 5b [2] b4 51 [2] a3 5a [2] b8 14 [2] 85 }

  condition:
    any of them
}