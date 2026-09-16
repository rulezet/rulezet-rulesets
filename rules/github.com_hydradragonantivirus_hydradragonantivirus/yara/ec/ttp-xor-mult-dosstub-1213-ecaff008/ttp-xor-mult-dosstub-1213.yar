rule TTP_XOR_MULT_DOSStub_1213 {
  strings:
    $key_1213 = { 46 7b [2] 32 63 [2] 75 61 [2] 32 70 [2] 7c 7c [2] 70 76 [2] 67 7d [2] 7c 33 [2] 41 }

  condition:
    any of them
}