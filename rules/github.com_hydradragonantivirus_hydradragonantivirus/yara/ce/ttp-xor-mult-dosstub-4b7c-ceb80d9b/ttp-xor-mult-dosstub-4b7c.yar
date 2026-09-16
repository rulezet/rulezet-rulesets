rule TTP_XOR_MULT_DOSStub_4b7c {
  strings:
    $key_4b7c = { 1f 14 [2] 6b 0c [2] 2c 0e [2] 6b 1f [2] 25 13 [2] 29 19 [2] 3e 12 [2] 25 5c [2] 18 }

  condition:
    any of them
}