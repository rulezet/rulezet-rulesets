rule TTP_XOR_MULT_DOSStub_0636 {
  strings:
    $key_0636 = { 52 5e [2] 26 46 [2] 61 44 [2] 26 55 [2] 68 59 [2] 64 53 [2] 73 58 [2] 68 16 [2] 55 }

  condition:
    any of them
}