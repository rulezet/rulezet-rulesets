rule TTP_XOR_MULT_DOSStub_147c {
  strings:
    $key_147c = { 40 14 [2] 34 0c [2] 73 0e [2] 34 1f [2] 7a 13 [2] 76 19 [2] 61 12 [2] 7a 5c [2] 47 }

  condition:
    any of them
}