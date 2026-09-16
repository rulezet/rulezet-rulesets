rule TTP_XOR_MULT_DOSStub_f02f {
  strings:
    $key_f02f = { a4 47 [2] d0 5f [2] 97 5d [2] d0 4c [2] 9e 40 [2] 92 4a [2] 85 41 [2] 9e 0f [2] a3 }

  condition:
    any of them
}