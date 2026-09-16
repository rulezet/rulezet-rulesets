rule TTP_XOR_MULT_DOSStub_68b4 {
  strings:
    $key_68b4 = { 3c dc [2] 48 c4 [2] 0f c6 [2] 48 d7 [2] 06 db [2] 0a d1 [2] 1d da [2] 06 94 [2] 3b }

  condition:
    any of them
}