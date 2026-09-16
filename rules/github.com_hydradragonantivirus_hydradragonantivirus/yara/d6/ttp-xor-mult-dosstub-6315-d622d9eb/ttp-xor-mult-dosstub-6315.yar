rule TTP_XOR_MULT_DOSStub_6315 {
  strings:
    $key_6315 = { 37 7d [2] 43 65 [2] 04 67 [2] 43 76 [2] 0d 7a [2] 01 70 [2] 16 7b [2] 0d 35 [2] 30 }

  condition:
    any of them
}