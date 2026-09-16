rule TTP_XOR_MULT_DOSStub_8feb {
  strings:
    $key_8feb = { db 83 [2] af 9b [2] e8 99 [2] af 88 [2] e1 84 [2] ed 8e [2] fa 85 [2] e1 cb [2] dc }

  condition:
    any of them
}