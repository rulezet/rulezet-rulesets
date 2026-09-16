rule TTP_XOR_MULT_DOSStub_3501 {
  strings:
    $key_3501 = { 61 69 [2] 15 71 [2] 52 73 [2] 15 62 [2] 5b 6e [2] 57 64 [2] 40 6f [2] 5b 21 [2] 66 }

  condition:
    any of them
}