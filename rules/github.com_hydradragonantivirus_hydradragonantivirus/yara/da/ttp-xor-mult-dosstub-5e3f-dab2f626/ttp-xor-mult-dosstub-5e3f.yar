rule TTP_XOR_MULT_DOSStub_5e3f {
  strings:
    $key_5e3f = { 0a 57 [2] 7e 4f [2] 39 4d [2] 7e 5c [2] 30 50 [2] 3c 5a [2] 2b 51 [2] 30 1f [2] 0d }

  condition:
    any of them
}