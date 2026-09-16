rule TTP_XOR_MULT_DOSStub_1f69 {
  strings:
    $key_1f69 = { 4b 01 [2] 3f 19 [2] 78 1b [2] 3f 0a [2] 71 06 [2] 7d 0c [2] 6a 07 [2] 71 49 [2] 4c }

  condition:
    any of them
}