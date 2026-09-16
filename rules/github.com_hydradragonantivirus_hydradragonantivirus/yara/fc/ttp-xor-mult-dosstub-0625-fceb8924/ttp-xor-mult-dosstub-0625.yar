rule TTP_XOR_MULT_DOSStub_0625 {
  strings:
    $key_0625 = { 52 4d [2] 26 55 [2] 61 57 [2] 26 46 [2] 68 4a [2] 64 40 [2] 73 4b [2] 68 05 [2] 55 }

  condition:
    any of them
}