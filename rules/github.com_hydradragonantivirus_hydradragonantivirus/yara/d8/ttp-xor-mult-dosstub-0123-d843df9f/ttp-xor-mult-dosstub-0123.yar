rule TTP_XOR_MULT_DOSStub_0123 {
  strings:
    $key_0123 = { 55 4b [2] 21 53 [2] 66 51 [2] 21 40 [2] 6f 4c [2] 63 46 [2] 74 4d [2] 6f 03 [2] 52 }

  condition:
    any of them
}