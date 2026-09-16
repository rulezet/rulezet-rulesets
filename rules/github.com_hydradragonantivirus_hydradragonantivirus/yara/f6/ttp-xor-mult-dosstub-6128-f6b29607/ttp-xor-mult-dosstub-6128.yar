rule TTP_XOR_MULT_DOSStub_6128 {
  strings:
    $key_6128 = { 35 40 [2] 41 58 [2] 06 5a [2] 41 4b [2] 0f 47 [2] 03 4d [2] 14 46 [2] 0f 08 [2] 32 }

  condition:
    any of them
}