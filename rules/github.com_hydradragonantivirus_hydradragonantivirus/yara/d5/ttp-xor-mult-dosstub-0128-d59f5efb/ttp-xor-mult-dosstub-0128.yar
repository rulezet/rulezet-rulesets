rule TTP_XOR_MULT_DOSStub_0128 {
  strings:
    $key_0128 = { 55 40 [2] 21 58 [2] 66 5a [2] 21 4b [2] 6f 47 [2] 63 4d [2] 74 46 [2] 6f 08 [2] 52 }

  condition:
    any of them
}