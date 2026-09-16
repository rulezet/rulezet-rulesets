rule TTP_XOR_MULT_DOSStub_6971 {
  strings:
    $key_6971 = { 3d 19 [2] 49 01 [2] 0e 03 [2] 49 12 [2] 07 1e [2] 0b 14 [2] 1c 1f [2] 07 51 [2] 3a }

  condition:
    any of them
}