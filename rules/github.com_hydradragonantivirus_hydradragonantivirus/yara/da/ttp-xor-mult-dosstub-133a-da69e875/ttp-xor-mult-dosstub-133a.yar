rule TTP_XOR_MULT_DOSStub_133a {
  strings:
    $key_133a = { 47 52 [2] 33 4a [2] 74 48 [2] 33 59 [2] 7d 55 [2] 71 5f [2] 66 54 [2] 7d 1a [2] 40 }

  condition:
    any of them
}