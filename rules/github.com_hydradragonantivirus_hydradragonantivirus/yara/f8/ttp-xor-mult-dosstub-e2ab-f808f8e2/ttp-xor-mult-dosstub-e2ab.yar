rule TTP_XOR_MULT_DOSStub_e2ab {
  strings:
    $key_e2ab = { b6 c3 [2] c2 db [2] 85 d9 [2] c2 c8 [2] 8c c4 [2] 80 ce [2] 97 c5 [2] 8c 8b [2] b1 }

  condition:
    any of them
}