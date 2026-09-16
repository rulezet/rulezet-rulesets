rule TTP_XOR_MULT_DOSStub_6501 {
  strings:
    $key_6501 = { 31 69 [2] 45 71 [2] 02 73 [2] 45 62 [2] 0b 6e [2] 07 64 [2] 10 6f [2] 0b 21 [2] 36 }

  condition:
    any of them
}