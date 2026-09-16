rule TTP_XOR_MULT_DOSStub_4b02 {
  strings:
    $key_4b02 = { 1f 6a [2] 6b 72 [2] 2c 70 [2] 6b 61 [2] 25 6d [2] 29 67 [2] 3e 6c [2] 25 22 [2] 18 }

  condition:
    any of them
}