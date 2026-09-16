rule TTP_XOR_MULT_DOSStub_4828 {
  strings:
    $key_4828 = { 1c 40 [2] 68 58 [2] 2f 5a [2] 68 4b [2] 26 47 [2] 2a 4d [2] 3d 46 [2] 26 08 [2] 1b }

  condition:
    any of them
}