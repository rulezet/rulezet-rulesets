rule TTP_XOR_MULT_DOSStub_c8b5 {
  strings:
    $key_c8b5 = { 9c dd [2] e8 c5 [2] af c7 [2] e8 d6 [2] a6 da [2] aa d0 [2] bd db [2] a6 95 [2] 9b }

  condition:
    any of them
}