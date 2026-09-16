rule TTP_XOR_MULT_DOSStub_28b4 {
  strings:
    $key_28b4 = { 7c dc [2] 08 c4 [2] 4f c6 [2] 08 d7 [2] 46 db [2] 4a d1 [2] 5d da [2] 46 94 [2] 7b }

  condition:
    any of them
}