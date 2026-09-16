rule TTP_XOR_MULT_DOSStub_16e3 {
  strings:
    $key_16e3 = { 42 8b [2] 36 93 [2] 71 91 [2] 36 80 [2] 78 8c [2] 74 86 [2] 63 8d [2] 78 c3 [2] 45 }

  condition:
    any of them
}