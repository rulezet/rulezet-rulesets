rule TTP_XOR_MULT_DOSStub_1818 {
  strings:
    $key_1818 = { 4c 70 [2] 38 68 [2] 7f 6a [2] 38 7b [2] 76 77 [2] 7a 7d [2] 6d 76 [2] 76 38 [2] 4b }

  condition:
    any of them
}