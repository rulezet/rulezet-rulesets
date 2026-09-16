rule TTP_XOR_MULT_DOSStub_f70d {
  strings:
    $key_f70d = { a3 65 [2] d7 7d [2] 90 7f [2] d7 6e [2] 99 62 [2] 95 68 [2] 82 63 [2] 99 2d [2] a4 }

  condition:
    any of them
}