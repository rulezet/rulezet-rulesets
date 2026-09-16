rule TTP_XOR_MULT_DOSStub_5d23 {
  strings:
    $key_5d23 = { 09 4b [2] 7d 53 [2] 3a 51 [2] 7d 40 [2] 33 4c [2] 3f 46 [2] 28 4d [2] 33 03 [2] 0e }

  condition:
    any of them
}