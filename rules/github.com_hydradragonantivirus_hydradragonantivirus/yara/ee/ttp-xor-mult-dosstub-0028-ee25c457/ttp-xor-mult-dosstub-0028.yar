rule TTP_XOR_MULT_DOSStub_0028 {
  strings:
    $key_0028 = { 54 40 [2] 20 58 [2] 67 5a [2] 20 4b [2] 6e 47 [2] 62 4d [2] 75 46 [2] 6e 08 [2] 53 }

  condition:
    any of them
}