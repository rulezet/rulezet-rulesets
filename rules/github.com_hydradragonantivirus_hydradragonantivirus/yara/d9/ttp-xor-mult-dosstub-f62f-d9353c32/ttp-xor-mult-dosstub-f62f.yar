rule TTP_XOR_MULT_DOSStub_f62f {
  strings:
    $key_f62f = { a2 47 [2] d6 5f [2] 91 5d [2] d6 4c [2] 98 40 [2] 94 4a [2] 83 41 [2] 98 0f [2] a5 }

  condition:
    any of them
}