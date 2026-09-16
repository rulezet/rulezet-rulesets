rule TTP_XOR_MULT_DOSStub_6715 {
  strings:
    $key_6715 = { 33 7d [2] 47 65 [2] 00 67 [2] 47 76 [2] 09 7a [2] 05 70 [2] 12 7b [2] 09 35 [2] 34 }

  condition:
    any of them
}