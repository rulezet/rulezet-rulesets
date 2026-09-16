rule TTP_XOR_MULT_DOSStub_71e8 {
  strings:
    $key_71e8 = { 25 80 [2] 51 98 [2] 16 9a [2] 51 8b [2] 1f 87 [2] 13 8d [2] 04 86 [2] 1f c8 [2] 22 }

  condition:
    any of them
}