rule TTP_XOR_MULT_DOSStub_6823 {
  strings:
    $key_6823 = { 3c 4b [2] 48 53 [2] 0f 51 [2] 48 40 [2] 06 4c [2] 0a 46 [2] 1d 4d [2] 06 03 [2] 3b }

  condition:
    any of them
}