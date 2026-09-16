rule TTP_XOR_MULT_DOSStub_21e8 {
  strings:
    $key_21e8 = { 75 80 [2] 01 98 [2] 46 9a [2] 01 8b [2] 4f 87 [2] 43 8d [2] 54 86 [2] 4f c8 [2] 72 }

  condition:
    any of them
}