rule TTP_XOR_MULT_DOSStub_27e3 {
  strings:
    $key_27e3 = { 73 8b [2] 07 93 [2] 40 91 [2] 07 80 [2] 49 8c [2] 45 86 [2] 52 8d [2] 49 c3 [2] 74 }

  condition:
    any of them
}