rule TTP_XOR_MULT_DOSStub_6a47 {
  strings:
    $key_6a47 = { 3e 2f [2] 4a 37 [2] 0d 35 [2] 4a 24 [2] 04 28 [2] 08 22 [2] 1f 29 [2] 04 67 [2] 39 }

  condition:
    any of them
}