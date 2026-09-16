rule TTP_XOR_MULT_DOSStub_5f25 {
  strings:
    $key_5f25 = { 0b 4d [2] 7f 55 [2] 38 57 [2] 7f 46 [2] 31 4a [2] 3d 40 [2] 2a 4b [2] 31 05 [2] 0c }

  condition:
    any of them
}