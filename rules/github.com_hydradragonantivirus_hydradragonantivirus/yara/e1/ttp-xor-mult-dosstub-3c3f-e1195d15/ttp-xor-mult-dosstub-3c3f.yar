rule TTP_XOR_MULT_DOSStub_3c3f {
  strings:
    $key_3c3f = { 68 57 [2] 1c 4f [2] 5b 4d [2] 1c 5c [2] 52 50 [2] 5e 5a [2] 49 51 [2] 52 1f [2] 6f }

  condition:
    any of them
}