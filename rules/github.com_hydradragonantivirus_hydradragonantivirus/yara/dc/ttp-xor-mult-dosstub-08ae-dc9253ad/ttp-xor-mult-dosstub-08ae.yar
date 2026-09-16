rule TTP_XOR_MULT_DOSStub_08ae {
  strings:
    $key_08ae = { 5c c6 [2] 28 de [2] 6f dc [2] 28 cd [2] 66 c1 [2] 6a cb [2] 7d c0 [2] 66 8e [2] 5b }

  condition:
    any of them
}