rule TTP_XOR_MULT_DOSStub_160f {
  strings:
    $key_160f = { 42 67 [2] 36 7f [2] 71 7d [2] 36 6c [2] 78 60 [2] 74 6a [2] 63 61 [2] 78 2f [2] 45 }

  condition:
    any of them
}