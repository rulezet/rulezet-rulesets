rule TTP_XOR_MULT_DOSStub_6915 {
  strings:
    $key_6915 = { 3d 7d [2] 49 65 [2] 0e 67 [2] 49 76 [2] 07 7a [2] 0b 70 [2] 1c 7b [2] 07 35 [2] 3a }

  condition:
    any of them
}