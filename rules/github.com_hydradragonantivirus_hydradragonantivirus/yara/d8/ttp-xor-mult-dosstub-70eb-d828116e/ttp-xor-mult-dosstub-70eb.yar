rule TTP_XOR_MULT_DOSStub_70eb {
  strings:
    $key_70eb = { 24 83 [2] 50 9b [2] 17 99 [2] 50 88 [2] 1e 84 [2] 12 8e [2] 05 85 [2] 1e cb [2] 23 }

  condition:
    any of them
}