rule TTP_XOR_MULT_DOSStub_1c33 {
  strings:
    $key_1c33 = { 48 5b [2] 3c 43 [2] 7b 41 [2] 3c 50 [2] 72 5c [2] 7e 56 [2] 69 5d [2] 72 13 [2] 4f }

  condition:
    any of them
}