rule TTP_XOR_MULT_DOSStub_620f {
  strings:
    $key_620f = { 36 67 [2] 42 7f [2] 05 7d [2] 42 6c [2] 0c 60 [2] 00 6a [2] 17 61 [2] 0c 2f [2] 31 }

  condition:
    any of them
}