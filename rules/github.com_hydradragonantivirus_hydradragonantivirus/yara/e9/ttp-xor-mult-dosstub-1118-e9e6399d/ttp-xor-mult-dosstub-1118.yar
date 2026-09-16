rule TTP_XOR_MULT_DOSStub_1118 {
  strings:
    $key_1118 = { 45 70 [2] 31 68 [2] 76 6a [2] 31 7b [2] 7f 77 [2] 73 7d [2] 64 76 [2] 7f 38 [2] 42 }

  condition:
    any of them
}