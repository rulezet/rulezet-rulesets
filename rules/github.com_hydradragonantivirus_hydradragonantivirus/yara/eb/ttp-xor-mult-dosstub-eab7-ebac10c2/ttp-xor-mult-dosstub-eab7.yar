rule TTP_XOR_MULT_DOSStub_eab7 {
  strings:
    $key_eab7 = { be df [2] ca c7 [2] 8d c5 [2] ca d4 [2] 84 d8 [2] 88 d2 [2] 9f d9 [2] 84 97 [2] b9 }

  condition:
    any of them
}