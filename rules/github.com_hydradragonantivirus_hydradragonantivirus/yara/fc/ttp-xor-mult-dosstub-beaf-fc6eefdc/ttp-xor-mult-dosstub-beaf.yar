rule TTP_XOR_MULT_DOSStub_beaf {
  strings:
    $key_beaf = { ea c7 [2] 9e df [2] d9 dd [2] 9e cc [2] d0 c0 [2] dc ca [2] cb c1 [2] d0 8f [2] ed }

  condition:
    any of them
}