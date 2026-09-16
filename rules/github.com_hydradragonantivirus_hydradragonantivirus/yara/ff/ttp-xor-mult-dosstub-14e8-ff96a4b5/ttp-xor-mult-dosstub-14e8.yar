rule TTP_XOR_MULT_DOSStub_14e8 {
  strings:
    $key_14e8 = { 40 80 [2] 34 98 [2] 73 9a [2] 34 8b [2] 7a 87 [2] 76 8d [2] 61 86 [2] 7a c8 [2] 47 }

  condition:
    any of them
}