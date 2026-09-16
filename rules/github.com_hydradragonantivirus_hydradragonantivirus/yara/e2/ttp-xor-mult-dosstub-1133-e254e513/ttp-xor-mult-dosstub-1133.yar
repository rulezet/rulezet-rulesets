rule TTP_XOR_MULT_DOSStub_1133 {
  strings:
    $key_1133 = { 45 5b [2] 31 43 [2] 76 41 [2] 31 50 [2] 7f 5c [2] 73 56 [2] 64 5d [2] 7f 13 [2] 42 }

  condition:
    any of them
}