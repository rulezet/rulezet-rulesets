rule TTP_XOR_MULT_DOSStub_4513 {
  strings:
    $key_4513 = { 11 7b [2] 65 63 [2] 22 61 [2] 65 70 [2] 2b 7c [2] 27 76 [2] 30 7d [2] 2b 33 [2] 16 }

  condition:
    any of them
}