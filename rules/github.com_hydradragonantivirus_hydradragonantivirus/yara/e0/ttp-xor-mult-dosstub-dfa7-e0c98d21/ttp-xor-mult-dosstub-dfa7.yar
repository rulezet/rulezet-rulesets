rule TTP_XOR_MULT_DOSStub_dfa7 {
  strings:
    $key_dfa7 = { 8b cf [2] ff d7 [2] b8 d5 [2] ff c4 [2] b1 c8 [2] bd c2 [2] aa c9 [2] b1 87 [2] 8c }

  condition:
    any of them
}