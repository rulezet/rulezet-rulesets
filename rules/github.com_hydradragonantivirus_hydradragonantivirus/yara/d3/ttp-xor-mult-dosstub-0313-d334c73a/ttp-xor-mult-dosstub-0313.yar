rule TTP_XOR_MULT_DOSStub_0313 {
  strings:
    $key_0313 = { 57 7b [2] 23 63 [2] 64 61 [2] 23 70 [2] 6d 7c [2] 61 76 [2] 76 7d [2] 6d 33 [2] 50 }

  condition:
    any of them
}