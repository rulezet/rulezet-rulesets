rule TTP_XOR_MULT_DOSStub_5f38 {
  strings:
    $key_5f38 = { 0b 50 [2] 7f 48 [2] 38 4a [2] 7f 5b [2] 31 57 [2] 3d 5d [2] 2a 56 [2] 31 18 [2] 0c }

  condition:
    any of them
}