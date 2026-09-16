rule TTP_XOR_MULT_DOSStub_4b35 {
  strings:
    $key_4b35 = { 1f 5d [2] 6b 45 [2] 2c 47 [2] 6b 56 [2] 25 5a [2] 29 50 [2] 3e 5b [2] 25 15 [2] 18 }

  condition:
    any of them
}