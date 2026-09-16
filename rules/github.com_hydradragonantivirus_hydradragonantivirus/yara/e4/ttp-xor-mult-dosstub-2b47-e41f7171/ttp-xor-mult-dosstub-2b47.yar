rule TTP_XOR_MULT_DOSStub_2b47 {
  strings:
    $key_2b47 = { 7f 2f [2] 0b 37 [2] 4c 35 [2] 0b 24 [2] 45 28 [2] 49 22 [2] 5e 29 [2] 45 67 [2] 78 }

  condition:
    any of them
}