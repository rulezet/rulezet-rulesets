rule TTP_XOR_MULT_DOSStub_1f28 {
  strings:
    $key_1f28 = { 4b 40 [2] 3f 58 [2] 78 5a [2] 3f 4b [2] 71 47 [2] 7d 4d [2] 6a 46 [2] 71 08 [2] 4c }

  condition:
    any of them
}