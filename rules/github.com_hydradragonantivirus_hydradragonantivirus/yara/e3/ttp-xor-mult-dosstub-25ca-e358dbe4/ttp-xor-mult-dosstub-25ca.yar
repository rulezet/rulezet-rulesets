rule TTP_XOR_MULT_DOSStub_25ca {
  strings:
    $key_25ca = { 71 a2 [2] 05 ba [2] 42 b8 [2] 05 a9 [2] 4b a5 [2] 47 af [2] 50 a4 [2] 4b ea [2] 76 }

  condition:
    any of them
}