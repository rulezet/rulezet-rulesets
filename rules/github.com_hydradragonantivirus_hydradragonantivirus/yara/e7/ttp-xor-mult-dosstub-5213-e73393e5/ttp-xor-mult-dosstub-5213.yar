rule TTP_XOR_MULT_DOSStub_5213 {
  strings:
    $key_5213 = { 06 7b [2] 72 63 [2] 35 61 [2] 72 70 [2] 3c 7c [2] 30 76 [2] 27 7d [2] 3c 33 [2] 01 }

  condition:
    any of them
}