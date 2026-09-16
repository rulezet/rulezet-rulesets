rule TTP_XOR_MULT_DOSStub_0d33 {
  strings:
    $key_0d33 = { 59 5b [2] 2d 43 [2] 6a 41 [2] 2d 50 [2] 63 5c [2] 6f 56 [2] 78 5d [2] 63 13 [2] 5e }

  condition:
    any of them
}