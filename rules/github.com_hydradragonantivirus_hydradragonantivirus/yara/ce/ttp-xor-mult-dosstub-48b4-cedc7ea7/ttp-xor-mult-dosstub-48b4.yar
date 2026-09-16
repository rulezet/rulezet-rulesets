rule TTP_XOR_MULT_DOSStub_48b4 {
  strings:
    $key_48b4 = { 1c dc [2] 68 c4 [2] 2f c6 [2] 68 d7 [2] 26 db [2] 2a d1 [2] 3d da [2] 26 94 [2] 1b }

  condition:
    any of them
}