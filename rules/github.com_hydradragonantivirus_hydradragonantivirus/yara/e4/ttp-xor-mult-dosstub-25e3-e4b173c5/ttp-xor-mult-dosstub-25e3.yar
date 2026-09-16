rule TTP_XOR_MULT_DOSStub_25e3 {
  strings:
    $key_25e3 = { 71 8b [2] 05 93 [2] 42 91 [2] 05 80 [2] 4b 8c [2] 47 86 [2] 50 8d [2] 4b c3 [2] 76 }

  condition:
    any of them
}