rule TTP_XOR_MULT_DOSStub_38a2 {
  strings:
    $key_38a2 = { 6c ca [2] 18 d2 [2] 5f d0 [2] 18 c1 [2] 56 cd [2] 5a c7 [2] 4d cc [2] 56 82 [2] 6b }

  condition:
    any of them
}