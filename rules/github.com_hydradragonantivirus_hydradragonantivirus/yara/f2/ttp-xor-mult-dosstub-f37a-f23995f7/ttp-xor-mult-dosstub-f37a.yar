rule TTP_XOR_MULT_DOSStub_f37a {
  strings:
    $key_f37a = { a7 12 [2] d3 0a [2] 94 08 [2] d3 19 [2] 9d 15 [2] 91 1f [2] 86 14 [2] 9d 5a [2] a0 }

  condition:
    any of them
}