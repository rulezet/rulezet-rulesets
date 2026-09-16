rule TTP_XOR_MULT_DOSStub_4861 {
  strings:
    $key_4861 = { 1c 09 [2] 68 11 [2] 2f 13 [2] 68 02 [2] 26 0e [2] 2a 04 [2] 3d 0f [2] 26 41 [2] 1b }

  condition:
    any of them
}