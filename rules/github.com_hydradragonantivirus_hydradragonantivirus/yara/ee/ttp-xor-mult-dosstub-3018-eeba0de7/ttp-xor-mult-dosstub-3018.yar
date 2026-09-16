rule TTP_XOR_MULT_DOSStub_3018 {
  strings:
    $key_3018 = { 64 70 [2] 10 68 [2] 57 6a [2] 10 7b [2] 5e 77 [2] 52 7d [2] 45 76 [2] 5e 38 [2] 63 }

  condition:
    any of them
}