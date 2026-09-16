rule TTP_XOR_MULT_DOSStub_1f79 {
  strings:
    $key_1f79 = { 4b 11 [2] 3f 09 [2] 78 0b [2] 3f 1a [2] 71 16 [2] 7d 1c [2] 6a 17 [2] 71 59 [2] 4c }

  condition:
    any of them
}