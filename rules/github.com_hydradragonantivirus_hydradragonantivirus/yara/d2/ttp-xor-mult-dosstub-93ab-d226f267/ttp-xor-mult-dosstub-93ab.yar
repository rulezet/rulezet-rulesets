rule TTP_XOR_MULT_DOSStub_93ab {
  strings:
    $key_93ab = { c7 c3 [2] b3 db [2] f4 d9 [2] b3 c8 [2] fd c4 [2] f1 ce [2] e6 c5 [2] fd 8b [2] c0 }

  condition:
    any of them
}