rule TTP_XOR_MULT_DOSStub_26eb {
  strings:
    $key_26eb = { 72 83 [2] 06 9b [2] 41 99 [2] 06 88 [2] 48 84 [2] 44 8e [2] 53 85 [2] 48 cb [2] 75 }

  condition:
    any of them
}