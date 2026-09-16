rule TTP_XOR_MULT_DOSStub_6ee5 {
  strings:
    $key_6ee5 = { 3a 8d [2] 4e 95 [2] 09 97 [2] 4e 86 [2] 00 8a [2] 0c 80 [2] 1b 8b [2] 00 c5 [2] 3d }

  condition:
    any of them
}