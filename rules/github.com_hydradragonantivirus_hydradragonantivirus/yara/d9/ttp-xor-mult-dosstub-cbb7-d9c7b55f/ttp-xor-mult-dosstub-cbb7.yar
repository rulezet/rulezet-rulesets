rule TTP_XOR_MULT_DOSStub_cbb7 {
  strings:
    $key_cbb7 = { 9f df [2] eb c7 [2] ac c5 [2] eb d4 [2] a5 d8 [2] a9 d2 [2] be d9 [2] a5 97 [2] 98 }

  condition:
    any of them
}