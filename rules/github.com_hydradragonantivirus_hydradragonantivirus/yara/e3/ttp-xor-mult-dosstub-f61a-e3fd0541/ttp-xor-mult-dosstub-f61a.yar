rule TTP_XOR_MULT_DOSStub_f61a {
  strings:
    $key_f61a = { a2 72 [2] d6 6a [2] 91 68 [2] d6 79 [2] 98 75 [2] 94 7f [2] 83 74 [2] 98 3a [2] a5 }

  condition:
    any of them
}