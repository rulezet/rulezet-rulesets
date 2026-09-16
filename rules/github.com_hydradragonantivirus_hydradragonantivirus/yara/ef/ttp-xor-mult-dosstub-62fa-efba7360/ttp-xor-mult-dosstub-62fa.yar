rule TTP_XOR_MULT_DOSStub_62fa {
  strings:
    $key_62fa = { 36 92 [2] 42 8a [2] 05 88 [2] 42 99 [2] 0c 95 [2] 00 9f [2] 17 94 [2] 0c da [2] 31 }

  condition:
    any of them
}