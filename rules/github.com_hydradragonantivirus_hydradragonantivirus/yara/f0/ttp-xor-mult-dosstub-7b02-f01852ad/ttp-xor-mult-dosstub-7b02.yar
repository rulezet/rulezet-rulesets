rule TTP_XOR_MULT_DOSStub_7b02 {
  strings:
    $key_7b02 = { 2f 6a [2] 5b 72 [2] 1c 70 [2] 5b 61 [2] 15 6d [2] 19 67 [2] 0e 6c [2] 15 22 [2] 28 }

  condition:
    any of them
}