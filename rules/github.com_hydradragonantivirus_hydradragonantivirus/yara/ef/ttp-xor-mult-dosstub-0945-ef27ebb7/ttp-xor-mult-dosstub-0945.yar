rule TTP_XOR_MULT_DOSStub_0945 {
  strings:
    $key_0945 = { 5d 2d [2] 29 35 [2] 6e 37 [2] 29 26 [2] 67 2a [2] 6b 20 [2] 7c 2b [2] 67 65 [2] 5a }

  condition:
    any of them
}