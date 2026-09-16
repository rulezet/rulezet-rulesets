rule TTP_XOR_MULT_DOSStub_e539 {
  strings:
    $key_e539 = { b1 51 [2] c5 49 [2] 82 4b [2] c5 5a [2] 8b 56 [2] 87 5c [2] 90 57 [2] 8b 19 [2] b6 }

  condition:
    any of them
}