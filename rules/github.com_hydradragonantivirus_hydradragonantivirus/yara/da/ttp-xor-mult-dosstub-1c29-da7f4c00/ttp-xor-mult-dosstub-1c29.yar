rule TTP_XOR_MULT_DOSStub_1c29 {
  strings:
    $key_1c29 = { 48 41 [2] 3c 59 [2] 7b 5b [2] 3c 4a [2] 72 46 [2] 7e 4c [2] 69 47 [2] 72 09 [2] 4f }

  condition:
    any of them
}