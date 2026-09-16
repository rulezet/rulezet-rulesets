rule TTP_XOR_MULT_DOSStub_6728 {
  strings:
    $key_6728 = { 33 40 [2] 47 58 [2] 00 5a [2] 47 4b [2] 09 47 [2] 05 4d [2] 12 46 [2] 09 08 [2] 34 }

  condition:
    any of them
}