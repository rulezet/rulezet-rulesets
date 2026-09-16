rule TTP_XOR_MULT_DOSStub_6a3f {
  strings:
    $key_6a3f = { 3e 57 [2] 4a 4f [2] 0d 4d [2] 4a 5c [2] 04 50 [2] 08 5a [2] 1f 51 [2] 04 1f [2] 39 }

  condition:
    any of them
}