rule TTP_XOR_MULT_DOSStub_6962 {
  strings:
    $key_6962 = { 3d 0a [2] 49 12 [2] 0e 10 [2] 49 01 [2] 07 0d [2] 0b 07 [2] 1c 0c [2] 07 42 [2] 3a }

  condition:
    any of them
}