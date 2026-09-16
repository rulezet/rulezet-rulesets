rule TTP_XOR_MULT_DOSStub_0b13 {
  strings:
    $key_0b13 = { 5f 7b [2] 2b 63 [2] 6c 61 [2] 2b 70 [2] 65 7c [2] 69 76 [2] 7e 7d [2] 65 33 [2] 58 }

  condition:
    any of them
}