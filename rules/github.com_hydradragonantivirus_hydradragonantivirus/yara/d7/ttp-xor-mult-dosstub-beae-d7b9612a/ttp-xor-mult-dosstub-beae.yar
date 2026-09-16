rule TTP_XOR_MULT_DOSStub_beae {
  strings:
    $key_beae = { ea c6 [2] 9e de [2] d9 dc [2] 9e cd [2] d0 c1 [2] dc cb [2] cb c0 [2] d0 8e [2] ed }

  condition:
    any of them
}