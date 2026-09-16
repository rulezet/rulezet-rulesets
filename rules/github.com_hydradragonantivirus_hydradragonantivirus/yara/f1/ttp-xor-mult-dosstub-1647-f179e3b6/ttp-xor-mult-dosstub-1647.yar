rule TTP_XOR_MULT_DOSStub_1647 {
  strings:
    $key_1647 = { 42 2f [2] 36 37 [2] 71 35 [2] 36 24 [2] 78 28 [2] 74 22 [2] 63 29 [2] 78 67 [2] 45 }

  condition:
    any of them
}