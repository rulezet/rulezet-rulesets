rule TTP_XOR_MULT_DOSStub_015a {
  strings:
    $key_015a = { 55 32 [2] 21 2a [2] 66 28 [2] 21 39 [2] 6f 35 [2] 63 3f [2] 74 34 [2] 6f 7a [2] 52 }

  condition:
    any of them
}