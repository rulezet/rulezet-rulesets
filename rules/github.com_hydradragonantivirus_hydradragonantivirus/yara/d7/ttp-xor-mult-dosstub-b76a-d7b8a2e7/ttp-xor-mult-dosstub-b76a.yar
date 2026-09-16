rule TTP_XOR_MULT_DOSStub_b76a {
  strings:
    $key_b76a = { e3 02 [2] 97 1a [2] d0 18 [2] 97 09 [2] d9 05 [2] d5 0f [2] c2 04 [2] d9 4a [2] e4 }

  condition:
    any of them
}