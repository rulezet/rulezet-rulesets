rule TTP_XOR_MULT_DOSStub_0928 {
  strings:
    $key_0928 = { 5d 40 [2] 29 58 [2] 6e 5a [2] 29 4b [2] 67 47 [2] 6b 4d [2] 7c 46 [2] 67 08 [2] 5a }

  condition:
    any of them
}