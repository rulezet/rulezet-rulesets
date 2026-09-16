rule TTP_XOR_MULT_DOSStub_c8b4 {
  strings:
    $key_c8b4 = { 9c dc [2] e8 c4 [2] af c6 [2] e8 d7 [2] a6 db [2] aa d1 [2] bd da [2] a6 94 [2] 9b }

  condition:
    any of them
}