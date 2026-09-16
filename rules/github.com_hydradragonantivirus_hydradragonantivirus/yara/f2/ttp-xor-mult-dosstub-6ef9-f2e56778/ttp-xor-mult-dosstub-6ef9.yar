rule TTP_XOR_MULT_DOSStub_6ef9 {
  strings:
    $key_6ef9 = { 3a 91 [2] 4e 89 [2] 09 8b [2] 4e 9a [2] 00 96 [2] 0c 9c [2] 1b 97 [2] 00 d9 [2] 3d }

  condition:
    any of them
}