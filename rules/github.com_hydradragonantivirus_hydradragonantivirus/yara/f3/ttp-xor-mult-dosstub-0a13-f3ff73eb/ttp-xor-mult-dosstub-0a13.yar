rule TTP_XOR_MULT_DOSStub_0a13 {
  strings:
    $key_0a13 = { 5e 7b [2] 2a 63 [2] 6d 61 [2] 2a 70 [2] 64 7c [2] 68 76 [2] 7f 7d [2] 64 33 [2] 59 }

  condition:
    any of them
}