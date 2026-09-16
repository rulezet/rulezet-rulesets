rule TTP_XOR_MULT_DOSStub_e5ca {
  strings:
    $key_e5ca = { b1 a2 [2] c5 ba [2] 82 b8 [2] c5 a9 [2] 8b a5 [2] 87 af [2] 90 a4 [2] 8b ea [2] b6 }

  condition:
    any of them
}