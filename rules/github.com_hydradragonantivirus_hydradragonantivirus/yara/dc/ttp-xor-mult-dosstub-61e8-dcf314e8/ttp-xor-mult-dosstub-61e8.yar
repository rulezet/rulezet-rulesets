rule TTP_XOR_MULT_DOSStub_61e8 {
  strings:
    $key_61e8 = { 35 80 [2] 41 98 [2] 06 9a [2] 41 8b [2] 0f 87 [2] 03 8d [2] 14 86 [2] 0f c8 [2] 32 }

  condition:
    any of them
}