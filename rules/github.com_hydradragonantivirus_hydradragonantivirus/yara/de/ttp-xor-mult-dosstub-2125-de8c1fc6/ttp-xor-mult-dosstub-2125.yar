rule TTP_XOR_MULT_DOSStub_2125 {
  strings:
    $key_2125 = { 75 4d [2] 01 55 [2] 46 57 [2] 01 46 [2] 4f 4a [2] 43 40 [2] 54 4b [2] 4f 05 [2] 72 }

  condition:
    any of them
}