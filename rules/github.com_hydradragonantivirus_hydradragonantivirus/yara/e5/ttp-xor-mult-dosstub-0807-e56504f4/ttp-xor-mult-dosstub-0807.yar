rule TTP_XOR_MULT_DOSStub_0807 {
  strings:
    $key_0807 = { 5c 6f [2] 28 77 [2] 6f 75 [2] 28 64 [2] 66 68 [2] 6a 62 [2] 7d 69 [2] 66 27 [2] 5b }

  condition:
    any of them
}