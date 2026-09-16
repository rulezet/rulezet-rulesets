rule TTP_XOR_MULT_DOSStub_5129 {
  strings:
    $key_5129 = { 05 41 [2] 71 59 [2] 36 5b [2] 71 4a [2] 3f 46 [2] 33 4c [2] 24 47 [2] 3f 09 [2] 02 }

  condition:
    any of them
}