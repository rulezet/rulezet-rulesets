rule TTP_XOR_MULT_DOSStub_aba9 {
  strings:
    $key_aba9 = { ff c1 [2] 8b d9 [2] cc db [2] 8b ca [2] c5 c6 [2] c9 cc [2] de c7 [2] c5 89 [2] f8 }

  condition:
    any of them
}