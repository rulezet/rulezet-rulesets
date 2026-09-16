rule TTP_XOR_MULT_DOSStub_3944 {
  strings:
    $key_3944 = { 6d 2c [2] 19 34 [2] 5e 36 [2] 19 27 [2] 57 2b [2] 5b 21 [2] 4c 2a [2] 57 64 [2] 6a }

  condition:
    any of them
}