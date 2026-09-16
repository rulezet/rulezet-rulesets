rule TTP_XOR_MULT_DOSStub_5f28 {
  strings:
    $key_5f28 = { 0b 40 [2] 7f 58 [2] 38 5a [2] 7f 4b [2] 31 47 [2] 3d 4d [2] 2a 46 [2] 31 08 [2] 0c }

  condition:
    any of them
}