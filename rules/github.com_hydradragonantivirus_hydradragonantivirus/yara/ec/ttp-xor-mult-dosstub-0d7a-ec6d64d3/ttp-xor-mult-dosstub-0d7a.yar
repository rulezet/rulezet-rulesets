rule TTP_XOR_MULT_DOSStub_0d7a {
  strings:
    $key_0d7a = { 59 12 [2] 2d 0a [2] 6a 08 [2] 2d 19 [2] 63 15 [2] 6f 1f [2] 78 14 [2] 63 5a [2] 5e }

  condition:
    any of them
}