rule TTP_XOR_MULT_DOSStub_72e3 {
  strings:
    $key_72e3 = { 26 8b [2] 52 93 [2] 15 91 [2] 52 80 [2] 1c 8c [2] 10 86 [2] 07 8d [2] 1c c3 [2] 21 }

  condition:
    any of them
}