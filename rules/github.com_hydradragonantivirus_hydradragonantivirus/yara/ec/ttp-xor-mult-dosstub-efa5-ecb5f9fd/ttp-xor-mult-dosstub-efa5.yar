rule TTP_XOR_MULT_DOSStub_efa5 {
  strings:
    $key_efa5 = { bb cd [2] cf d5 [2] 88 d7 [2] cf c6 [2] 81 ca [2] 8d c0 [2] 9a cb [2] 81 85 [2] bc }

  condition:
    any of them
}