rule TTP_XOR_MULT_DOSStub_2213 {
  strings:
    $key_2213 = { 76 7b [2] 02 63 [2] 45 61 [2] 02 70 [2] 4c 7c [2] 40 76 [2] 57 7d [2] 4c 33 [2] 71 }

  condition:
    any of them
}