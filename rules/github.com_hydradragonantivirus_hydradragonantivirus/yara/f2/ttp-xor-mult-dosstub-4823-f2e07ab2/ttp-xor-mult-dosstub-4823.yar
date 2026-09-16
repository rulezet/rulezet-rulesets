rule TTP_XOR_MULT_DOSStub_4823 {
  strings:
    $key_4823 = { 1c 4b [2] 68 53 [2] 2f 51 [2] 68 40 [2] 26 4c [2] 2a 46 [2] 3d 4d [2] 26 03 [2] 1b }

  condition:
    any of them
}