rule TTP_XOR_MULT_DOSStub_2b49 {
  strings:
    $key_2b49 = { 7f 21 [2] 0b 39 [2] 4c 3b [2] 0b 2a [2] 45 26 [2] 49 2c [2] 5e 27 [2] 45 69 [2] 78 }

  condition:
    any of them
}