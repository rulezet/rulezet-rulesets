rule TTP_XOR_MULT_DOSStub_0500 {
  strings:
    $key_0500 = { 51 68 [2] 25 70 [2] 62 72 [2] 25 63 [2] 6b 6f [2] 67 65 [2] 70 6e [2] 6b 20 [2] 56 }

  condition:
    any of them
}