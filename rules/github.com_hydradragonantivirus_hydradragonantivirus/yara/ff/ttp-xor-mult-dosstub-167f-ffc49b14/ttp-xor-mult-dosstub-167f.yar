rule TTP_XOR_MULT_DOSStub_167f {
  strings:
    $key_167f = { 42 17 [2] 36 0f [2] 71 0d [2] 36 1c [2] 78 10 [2] 74 1a [2] 63 11 [2] 78 5f [2] 45 }

  condition:
    any of them
}