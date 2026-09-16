rule TTP_XOR_MULT_DOSStub_3015 {
  strings:
    $key_3015 = { 64 7d [2] 10 65 [2] 57 67 [2] 10 76 [2] 5e 7a [2] 52 70 [2] 45 7b [2] 5e 35 [2] 63 }

  condition:
    any of them
}