rule TTP_XOR_MULT_DOSStub_3728 {
  strings:
    $key_3728 = { 63 40 [2] 17 58 [2] 50 5a [2] 17 4b [2] 59 47 [2] 55 4d [2] 42 46 [2] 59 08 [2] 64 }

  condition:
    any of them
}