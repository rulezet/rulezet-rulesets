rule TTP_XOR_MULT_DOSStub_0831 {
  strings:
    $key_0831 = { 5c 59 [2] 28 41 [2] 6f 43 [2] 28 52 [2] 66 5e [2] 6a 54 [2] 7d 5f [2] 66 11 [2] 5b }

  condition:
    any of them
}