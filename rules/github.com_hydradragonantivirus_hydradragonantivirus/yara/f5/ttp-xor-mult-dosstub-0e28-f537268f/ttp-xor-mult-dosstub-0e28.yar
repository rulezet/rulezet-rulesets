rule TTP_XOR_MULT_DOSStub_0e28 {
  strings:
    $key_0e28 = { 5a 40 [2] 2e 58 [2] 69 5a [2] 2e 4b [2] 60 47 [2] 6c 4d [2] 7b 46 [2] 60 08 [2] 5d }

  condition:
    any of them
}