rule TTP_XOR_MULT_DOSStub_7ae3 {
  strings:
    $key_7ae3 = { 2e 8b [2] 5a 93 [2] 1d 91 [2] 5a 80 [2] 14 8c [2] 18 86 [2] 0f 8d [2] 14 c3 [2] 29 }

  condition:
    any of them
}