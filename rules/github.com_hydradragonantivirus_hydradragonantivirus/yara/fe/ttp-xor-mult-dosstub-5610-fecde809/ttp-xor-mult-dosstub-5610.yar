rule TTP_XOR_MULT_DOSStub_5610 {
  strings:
    $key_5610 = { 02 78 [2] 76 60 [2] 31 62 [2] 76 73 [2] 38 7f [2] 34 75 [2] 23 7e [2] 38 30 [2] 05 }

  condition:
    any of them
}