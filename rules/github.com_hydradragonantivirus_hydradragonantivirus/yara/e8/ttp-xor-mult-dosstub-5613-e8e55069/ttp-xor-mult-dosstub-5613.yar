rule TTP_XOR_MULT_DOSStub_5613 {
  strings:
    $key_5613 = { 02 7b [2] 76 63 [2] 31 61 [2] 76 70 [2] 38 7c [2] 34 76 [2] 23 7d [2] 38 33 [2] 05 }

  condition:
    any of them
}