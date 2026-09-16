rule TTP_XOR_MULT_DOSStub_1c25 {
  strings:
    $key_1c25 = { 48 4d [2] 3c 55 [2] 7b 57 [2] 3c 46 [2] 72 4a [2] 7e 40 [2] 69 4b [2] 72 05 [2] 4f }

  condition:
    any of them
}