rule TTP_XOR_MULT_DOSStub_1651 {
  strings:
    $key_1651 = { 42 39 [2] 36 21 [2] 71 23 [2] 36 32 [2] 78 3e [2] 74 34 [2] 63 3f [2] 78 71 [2] 45 }

  condition:
    any of them
}