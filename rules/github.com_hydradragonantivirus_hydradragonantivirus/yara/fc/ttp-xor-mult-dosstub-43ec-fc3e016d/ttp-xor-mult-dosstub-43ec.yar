rule TTP_XOR_MULT_DOSStub_43ec {
  strings:
    $key_43ec = { 17 84 [2] 63 9c [2] 24 9e [2] 63 8f [2] 2d 83 [2] 21 89 [2] 36 82 [2] 2d cc [2] 10 }

  condition:
    any of them
}