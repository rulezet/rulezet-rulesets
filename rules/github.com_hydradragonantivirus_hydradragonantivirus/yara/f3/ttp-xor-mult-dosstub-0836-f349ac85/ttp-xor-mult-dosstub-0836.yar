rule TTP_XOR_MULT_DOSStub_0836 {
  strings:
    $key_0836 = { 5c 5e [2] 28 46 [2] 6f 44 [2] 28 55 [2] 66 59 [2] 6a 53 [2] 7d 58 [2] 66 16 [2] 5b }

  condition:
    any of them
}