rule TTP_XOR_MULT_DOSStub_eab5 {
  strings:
    $key_eab5 = { be dd [2] ca c5 [2] 8d c7 [2] ca d6 [2] 84 da [2] 88 d0 [2] 9f db [2] 84 95 [2] b9 }

  condition:
    any of them
}