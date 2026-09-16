rule TTP_XOR_MULT_DOSStub_432c {
  strings:
    $key_432c = { 17 44 [2] 63 5c [2] 24 5e [2] 63 4f [2] 2d 43 [2] 21 49 [2] 36 42 [2] 2d 0c [2] 10 }

  condition:
    any of them
}