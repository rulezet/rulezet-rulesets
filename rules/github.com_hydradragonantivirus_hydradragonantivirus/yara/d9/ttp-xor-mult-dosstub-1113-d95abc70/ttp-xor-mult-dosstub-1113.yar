rule TTP_XOR_MULT_DOSStub_1113 {
  strings:
    $key_1113 = { 45 7b [2] 31 63 [2] 76 61 [2] 31 70 [2] 7f 7c [2] 73 76 [2] 64 7d [2] 7f 33 [2] 42 }

  condition:
    any of them
}