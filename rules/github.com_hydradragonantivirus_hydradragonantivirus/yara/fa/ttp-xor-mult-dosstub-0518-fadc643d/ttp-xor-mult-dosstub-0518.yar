rule TTP_XOR_MULT_DOSStub_0518 {
  strings:
    $key_0518 = { 51 70 [2] 25 68 [2] 62 6a [2] 25 7b [2] 6b 77 [2] 67 7d [2] 70 76 [2] 6b 38 [2] 56 }

  condition:
    any of them
}