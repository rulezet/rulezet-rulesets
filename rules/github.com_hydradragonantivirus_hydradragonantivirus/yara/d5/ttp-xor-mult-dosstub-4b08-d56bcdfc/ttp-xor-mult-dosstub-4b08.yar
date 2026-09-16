rule TTP_XOR_MULT_DOSStub_4b08 {
  strings:
    $key_4b08 = { 1f 60 [2] 6b 78 [2] 2c 7a [2] 6b 6b [2] 25 67 [2] 29 6d [2] 3e 66 [2] 25 28 [2] 18 }

  condition:
    any of them
}