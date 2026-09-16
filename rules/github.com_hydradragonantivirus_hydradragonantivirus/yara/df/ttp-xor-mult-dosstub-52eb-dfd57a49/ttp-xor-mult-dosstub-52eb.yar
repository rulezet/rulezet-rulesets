rule TTP_XOR_MULT_DOSStub_52eb {
  strings:
    $key_52eb = { 06 83 [2] 72 9b [2] 35 99 [2] 72 88 [2] 3c 84 [2] 30 8e [2] 27 85 [2] 3c cb [2] 01 }

  condition:
    any of them
}