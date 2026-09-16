rule TTP_XOR_MULT_DOSStub_4839 {
  strings:
    $key_4839 = { 1c 51 [2] 68 49 [2] 2f 4b [2] 68 5a [2] 26 56 [2] 2a 5c [2] 3d 57 [2] 26 19 [2] 1b }

  condition:
    any of them
}