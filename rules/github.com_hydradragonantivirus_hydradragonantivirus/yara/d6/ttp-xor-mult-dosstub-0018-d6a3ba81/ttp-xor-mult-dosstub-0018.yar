rule TTP_XOR_MULT_DOSStub_0018 {
  strings:
    $key_0018 = { 54 70 [2] 20 68 [2] 67 6a [2] 20 7b [2] 6e 77 [2] 62 7d [2] 75 76 [2] 6e 38 [2] 53 }

  condition:
    any of them
}