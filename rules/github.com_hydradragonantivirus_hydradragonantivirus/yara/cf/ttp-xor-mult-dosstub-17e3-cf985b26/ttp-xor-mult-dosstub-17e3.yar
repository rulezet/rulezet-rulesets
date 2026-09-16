rule TTP_XOR_MULT_DOSStub_17e3 {
  strings:
    $key_17e3 = { 43 8b [2] 37 93 [2] 70 91 [2] 37 80 [2] 79 8c [2] 75 86 [2] 62 8d [2] 79 c3 [2] 44 }

  condition:
    any of them
}