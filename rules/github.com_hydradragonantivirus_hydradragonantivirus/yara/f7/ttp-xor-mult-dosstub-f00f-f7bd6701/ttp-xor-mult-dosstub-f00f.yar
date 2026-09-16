rule TTP_XOR_MULT_DOSStub_f00f {
  strings:
    $key_f00f = { a4 67 [2] d0 7f [2] 97 7d [2] d0 6c [2] 9e 60 [2] 92 6a [2] 85 61 [2] 9e 2f [2] a3 }

  condition:
    any of them
}