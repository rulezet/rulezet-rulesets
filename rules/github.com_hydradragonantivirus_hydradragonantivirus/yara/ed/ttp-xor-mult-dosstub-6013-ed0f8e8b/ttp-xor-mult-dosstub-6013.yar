rule TTP_XOR_MULT_DOSStub_6013 {
  strings:
    $key_6013 = { 34 7b [2] 40 63 [2] 07 61 [2] 40 70 [2] 0e 7c [2] 02 76 [2] 15 7d [2] 0e 33 [2] 33 }

  condition:
    any of them
}