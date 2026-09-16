rule TTP_XOR_MULT_DOSStub_cbba {
  strings:
    $key_cbba = { 9f d2 [2] eb ca [2] ac c8 [2] eb d9 [2] a5 d5 [2] a9 df [2] be d4 [2] a5 9a [2] 98 }

  condition:
    any of them
}