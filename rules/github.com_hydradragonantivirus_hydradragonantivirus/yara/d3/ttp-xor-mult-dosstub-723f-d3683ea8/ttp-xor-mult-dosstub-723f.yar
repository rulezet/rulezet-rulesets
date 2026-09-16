rule TTP_XOR_MULT_DOSStub_723f {
  strings:
    $key_723f = { 26 57 [2] 52 4f [2] 15 4d [2] 52 5c [2] 1c 50 [2] 10 5a [2] 07 51 [2] 1c 1f [2] 21 }

  condition:
    any of them
}