rule TTP_XOR_MULT_DOSStub_2210 {
  strings:
    $key_2210 = { 76 78 [2] 02 60 [2] 45 62 [2] 02 73 [2] 4c 7f [2] 40 75 [2] 57 7e [2] 4c 30 [2] 71 }

  condition:
    any of them
}