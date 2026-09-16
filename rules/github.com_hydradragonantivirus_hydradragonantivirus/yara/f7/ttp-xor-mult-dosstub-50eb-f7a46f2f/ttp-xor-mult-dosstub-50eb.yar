rule TTP_XOR_MULT_DOSStub_50eb {
  strings:
    $key_50eb = { 04 83 [2] 70 9b [2] 37 99 [2] 70 88 [2] 3e 84 [2] 32 8e [2] 25 85 [2] 3e cb [2] 03 }

  condition:
    any of them
}