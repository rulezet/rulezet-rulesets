rule TTP_XOR_MULT_DOSStub_3e5f {
  strings:
    $key_3e5f = { 6a 37 [2] 1e 2f [2] 59 2d [2] 1e 3c [2] 50 30 [2] 5c 3a [2] 4b 31 [2] 50 7f [2] 6d }

  condition:
    any of them
}