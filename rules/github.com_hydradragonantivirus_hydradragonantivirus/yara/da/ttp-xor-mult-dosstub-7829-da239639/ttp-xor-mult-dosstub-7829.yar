rule TTP_XOR_MULT_DOSStub_7829 {
  strings:
    $key_7829 = { 2c 41 [2] 58 59 [2] 1f 5b [2] 58 4a [2] 16 46 [2] 1a 4c [2] 0d 47 [2] 16 09 [2] 2b }

  condition:
    any of them
}