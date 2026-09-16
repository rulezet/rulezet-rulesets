rule TTP_XOR_MULT_DOSStub_f60a {
  strings:
    $key_f60a = { a2 62 [2] d6 7a [2] 91 78 [2] d6 69 [2] 98 65 [2] 94 6f [2] 83 64 [2] 98 2a [2] a5 }

  condition:
    any of them
}