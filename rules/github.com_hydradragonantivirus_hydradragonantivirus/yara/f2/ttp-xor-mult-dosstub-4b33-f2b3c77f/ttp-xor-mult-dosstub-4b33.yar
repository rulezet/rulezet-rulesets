rule TTP_XOR_MULT_DOSStub_4b33 {
  strings:
    $key_4b33 = { 1f 5b [2] 6b 43 [2] 2c 41 [2] 6b 50 [2] 25 5c [2] 29 56 [2] 3e 5d [2] 25 13 [2] 18 }

  condition:
    any of them
}