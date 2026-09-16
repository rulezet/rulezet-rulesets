rule TTP_XOR_MULT_DOSStub_52e3 {
  strings:
    $key_52e3 = { 06 8b [2] 72 93 [2] 35 91 [2] 72 80 [2] 3c 8c [2] 30 86 [2] 27 8d [2] 3c c3 [2] 01 }

  condition:
    any of them
}