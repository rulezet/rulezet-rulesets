rule TTP_XOR_MULT_DOSStub_093f {
  strings:
    $key_093f = { 5d 57 [2] 29 4f [2] 6e 4d [2] 29 5c [2] 67 50 [2] 6b 5a [2] 7c 51 [2] 67 1f [2] 5a }

  condition:
    any of them
}