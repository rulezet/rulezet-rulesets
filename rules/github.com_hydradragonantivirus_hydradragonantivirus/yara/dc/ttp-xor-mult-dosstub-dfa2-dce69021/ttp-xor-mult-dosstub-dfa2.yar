rule TTP_XOR_MULT_DOSStub_dfa2 {
  strings:
    $key_dfa2 = { 8b ca [2] ff d2 [2] b8 d0 [2] ff c1 [2] b1 cd [2] bd c7 [2] aa cc [2] b1 82 [2] 8c }

  condition:
    any of them
}