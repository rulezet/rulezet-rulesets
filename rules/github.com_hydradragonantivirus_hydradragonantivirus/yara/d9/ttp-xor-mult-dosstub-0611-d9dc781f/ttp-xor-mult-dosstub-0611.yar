rule TTP_XOR_MULT_DOSStub_0611 {
  strings:
    $key_0611 = { 52 79 [2] 26 61 [2] 61 63 [2] 26 72 [2] 68 7e [2] 64 74 [2] 73 7f [2] 68 31 [2] 55 }

  condition:
    any of them
}