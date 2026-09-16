rule TTP_XOR_MULT_DOSStub_4f24 {
  strings:
    $key_4f24 = { 1b 4c [2] 6f 54 [2] 28 56 [2] 6f 47 [2] 21 4b [2] 2d 41 [2] 3a 4a [2] 21 04 [2] 1c }

  condition:
    any of them
}