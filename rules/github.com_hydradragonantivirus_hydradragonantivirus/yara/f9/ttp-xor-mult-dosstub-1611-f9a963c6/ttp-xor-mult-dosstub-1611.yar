rule TTP_XOR_MULT_DOSStub_1611 {
  strings:
    $key_1611 = { 42 79 [2] 36 61 [2] 71 63 [2] 36 72 [2] 78 7e [2] 74 74 [2] 63 7f [2] 78 31 [2] 45 }

  condition:
    any of them
}