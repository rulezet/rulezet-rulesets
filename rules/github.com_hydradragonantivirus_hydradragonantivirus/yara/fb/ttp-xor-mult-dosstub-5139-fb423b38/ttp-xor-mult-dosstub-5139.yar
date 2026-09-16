rule TTP_XOR_MULT_DOSStub_5139 {
  strings:
    $key_5139 = { 05 51 [2] 71 49 [2] 36 4b [2] 71 5a [2] 3f 56 [2] 33 5c [2] 24 57 [2] 3f 19 [2] 02 }

  condition:
    any of them
}