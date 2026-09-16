rule TTP_XOR_MULT_DOSStub_abba {
  strings:
    $key_abba = { ff d2 [2] 8b ca [2] cc c8 [2] 8b d9 [2] c5 d5 [2] c9 df [2] de d4 [2] c5 9a [2] f8 }

  condition:
    any of them
}