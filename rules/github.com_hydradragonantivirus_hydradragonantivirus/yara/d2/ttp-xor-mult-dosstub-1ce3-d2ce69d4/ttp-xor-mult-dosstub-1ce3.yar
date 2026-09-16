rule TTP_XOR_MULT_DOSStub_1ce3 {
  strings:
    $key_1ce3 = { 48 8b [2] 3c 93 [2] 7b 91 [2] 3c 80 [2] 72 8c [2] 7e 86 [2] 69 8d [2] 72 c3 [2] 4f }

  condition:
    any of them
}