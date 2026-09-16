rule TTP_XOR_MULT_DOSStub_0e37 {
  strings:
    $key_0e37 = { 5a 5f [2] 2e 47 [2] 69 45 [2] 2e 54 [2] 60 58 [2] 6c 52 [2] 7b 59 [2] 60 17 [2] 5d }

  condition:
    any of them
}