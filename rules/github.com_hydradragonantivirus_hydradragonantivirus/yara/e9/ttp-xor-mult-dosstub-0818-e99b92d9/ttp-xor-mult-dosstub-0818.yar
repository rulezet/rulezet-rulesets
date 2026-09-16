rule TTP_XOR_MULT_DOSStub_0818 {
  strings:
    $key_0818 = { 5c 70 [2] 28 68 [2] 6f 6a [2] 28 7b [2] 66 77 [2] 6a 7d [2] 7d 76 [2] 66 38 [2] 5b }

  condition:
    any of them
}