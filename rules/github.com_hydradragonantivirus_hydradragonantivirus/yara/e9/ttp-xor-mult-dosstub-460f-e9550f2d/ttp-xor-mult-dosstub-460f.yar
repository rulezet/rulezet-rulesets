rule TTP_XOR_MULT_DOSStub_460f {
  strings:
    $key_460f = { 12 67 [2] 66 7f [2] 21 7d [2] 66 6c [2] 28 60 [2] 24 6a [2] 33 61 [2] 28 2f [2] 15 }

  condition:
    any of them
}