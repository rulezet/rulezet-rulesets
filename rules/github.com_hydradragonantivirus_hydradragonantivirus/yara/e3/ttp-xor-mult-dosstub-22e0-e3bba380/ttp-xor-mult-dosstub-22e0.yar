rule TTP_XOR_MULT_DOSStub_22e0 {
  strings:
    $key_22e0 = { 76 88 [2] 02 90 [2] 45 92 [2] 02 83 [2] 4c 8f [2] 40 85 [2] 57 8e [2] 4c c0 [2] 71 }

  condition:
    any of them
}