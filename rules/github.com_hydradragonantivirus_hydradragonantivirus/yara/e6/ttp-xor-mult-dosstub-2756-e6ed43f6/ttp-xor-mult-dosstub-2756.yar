rule TTP_XOR_MULT_DOSStub_2756 {
  strings:
    $key_2756 = { 73 3e [2] 07 26 [2] 40 24 [2] 07 35 [2] 49 39 [2] 45 33 [2] 52 38 [2] 49 76 [2] 74 }

  condition:
    any of them
}