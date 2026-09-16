rule TTP_XOR_MULT_DOSStub_33e3 {
  strings:
    $key_33e3 = { 67 8b [2] 13 93 [2] 54 91 [2] 13 80 [2] 5d 8c [2] 51 86 [2] 46 8d [2] 5d c3 [2] 60 }

  condition:
    any of them
}