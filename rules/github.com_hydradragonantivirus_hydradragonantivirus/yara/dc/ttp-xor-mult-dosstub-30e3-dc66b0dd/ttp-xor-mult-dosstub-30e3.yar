rule TTP_XOR_MULT_DOSStub_30e3 {
  strings:
    $key_30e3 = { 64 8b [2] 10 93 [2] 57 91 [2] 10 80 [2] 5e 8c [2] 52 86 [2] 45 8d [2] 5e c3 [2] 63 }

  condition:
    any of them
}