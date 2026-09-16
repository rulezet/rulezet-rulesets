rule TTP_XOR_MULT_DOSStub_3017 {
  strings:
    $key_3017 = { 64 7f [2] 10 67 [2] 57 65 [2] 10 74 [2] 5e 78 [2] 52 72 [2] 45 79 [2] 5e 37 [2] 63 }

  condition:
    any of them
}