rule TTP_XOR_MULT_DOSStub_500f {
  strings:
    $key_500f = { 04 67 [2] 70 7f [2] 37 7d [2] 70 6c [2] 3e 60 [2] 32 6a [2] 25 61 [2] 3e 2f [2] 03 }

  condition:
    any of them
}