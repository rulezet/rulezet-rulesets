rule TTP_XOR_MULT_DOSStub_08e3 {
  strings:
    $key_08e3 = { 5c 8b [2] 28 93 [2] 6f 91 [2] 28 80 [2] 66 8c [2] 6a 86 [2] 7d 8d [2] 66 c3 [2] 5b }

  condition:
    any of them
}