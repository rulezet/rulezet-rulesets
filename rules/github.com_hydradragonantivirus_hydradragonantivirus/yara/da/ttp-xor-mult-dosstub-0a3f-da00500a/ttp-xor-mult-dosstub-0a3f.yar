rule TTP_XOR_MULT_DOSStub_0a3f {
  strings:
    $key_0a3f = { 5e 57 [2] 2a 4f [2] 6d 4d [2] 2a 5c [2] 64 50 [2] 68 5a [2] 7f 51 [2] 64 1f [2] 59 }

  condition:
    any of them
}