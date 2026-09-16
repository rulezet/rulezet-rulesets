rule TTP_XOR_MULT_DOSStub_1f3a {
  strings:
    $key_1f3a = { 4b 52 [2] 3f 4a [2] 78 48 [2] 3f 59 [2] 71 55 [2] 7d 5f [2] 6a 54 [2] 71 1a [2] 4c }

  condition:
    any of them
}