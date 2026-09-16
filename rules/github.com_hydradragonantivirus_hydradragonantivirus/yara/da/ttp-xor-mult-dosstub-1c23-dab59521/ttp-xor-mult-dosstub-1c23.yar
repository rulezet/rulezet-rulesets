rule TTP_XOR_MULT_DOSStub_1c23 {
  strings:
    $key_1c23 = { 48 4b [2] 3c 53 [2] 7b 51 [2] 3c 40 [2] 72 4c [2] 7e 46 [2] 69 4d [2] 72 03 [2] 4f }

  condition:
    any of them
}