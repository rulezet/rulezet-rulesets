rule TTP_XOR_MULT_DOSStub_f70f {
  strings:
    $key_f70f = { a3 67 [2] d7 7f [2] 90 7d [2] d7 6c [2] 99 60 [2] 95 6a [2] 82 61 [2] 99 2f [2] a4 }

  condition:
    any of them
}