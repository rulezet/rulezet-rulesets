rule TTP_XOR_MULT_DOSStub_323f {
  strings:
    $key_323f = { 66 57 [2] 12 4f [2] 55 4d [2] 12 5c [2] 5c 50 [2] 50 5a [2] 47 51 [2] 5c 1f [2] 61 }

  condition:
    any of them
}