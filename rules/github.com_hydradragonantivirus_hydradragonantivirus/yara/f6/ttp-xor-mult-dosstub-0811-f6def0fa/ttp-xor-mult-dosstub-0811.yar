rule TTP_XOR_MULT_DOSStub_0811 {
  strings:
    $key_0811 = { 5c 79 [2] 28 61 [2] 6f 63 [2] 28 72 [2] 66 7e [2] 6a 74 [2] 7d 7f [2] 66 31 [2] 5b }

  condition:
    any of them
}