rule TTP_XOR_MULT_DOSStub_720f {
  strings:
    $key_720f = { 26 67 [2] 52 7f [2] 15 7d [2] 52 6c [2] 1c 60 [2] 10 6a [2] 07 61 [2] 1c 2f [2] 21 }

  condition:
    any of them
}