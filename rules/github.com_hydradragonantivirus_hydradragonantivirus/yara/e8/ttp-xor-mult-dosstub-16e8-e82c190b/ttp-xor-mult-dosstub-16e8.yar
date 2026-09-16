rule TTP_XOR_MULT_DOSStub_16e8 {
  strings:
    $key_16e8 = { 42 80 [2] 36 98 [2] 71 9a [2] 36 8b [2] 78 87 [2] 74 8d [2] 63 86 [2] 78 c8 [2] 45 }

  condition:
    any of them
}