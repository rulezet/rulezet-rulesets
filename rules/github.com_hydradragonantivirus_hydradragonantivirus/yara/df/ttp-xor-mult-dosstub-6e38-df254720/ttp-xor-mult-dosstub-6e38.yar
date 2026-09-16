rule TTP_XOR_MULT_DOSStub_6e38 {
  strings:
    $key_6e38 = { 3a 50 [2] 4e 48 [2] 09 4a [2] 4e 5b [2] 00 57 [2] 0c 5d [2] 1b 56 [2] 00 18 [2] 3d }

  condition:
    any of them
}