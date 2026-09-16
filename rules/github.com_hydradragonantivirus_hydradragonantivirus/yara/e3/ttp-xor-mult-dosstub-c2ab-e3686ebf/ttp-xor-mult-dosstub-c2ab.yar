rule TTP_XOR_MULT_DOSStub_c2ab {
  strings:
    $key_c2ab = { 96 c3 [2] e2 db [2] a5 d9 [2] e2 c8 [2] ac c4 [2] a0 ce [2] b7 c5 [2] ac 8b [2] 91 }

  condition:
    any of them
}