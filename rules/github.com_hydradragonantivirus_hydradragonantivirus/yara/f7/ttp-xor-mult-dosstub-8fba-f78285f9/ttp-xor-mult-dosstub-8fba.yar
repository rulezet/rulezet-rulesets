rule TTP_XOR_MULT_DOSStub_8fba {
  strings:
    $key_8fba = { db d2 [2] af ca [2] e8 c8 [2] af d9 [2] e1 d5 [2] ed df [2] fa d4 [2] e1 9a [2] dc }

  condition:
    any of them
}