rule TTP_XOR_MULT_DOSStub_0df8 {
  strings:
    $key_0df8 = { 59 90 [2] 2d 88 [2] 6a 8a [2] 2d 9b [2] 63 97 [2] 6f 9d [2] 78 96 [2] 63 d8 [2] 5e }

  condition:
    any of them
}