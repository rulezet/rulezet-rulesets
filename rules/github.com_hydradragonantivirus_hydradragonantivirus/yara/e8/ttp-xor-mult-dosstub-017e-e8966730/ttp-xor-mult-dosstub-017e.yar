rule TTP_XOR_MULT_DOSStub_017e {
  strings:
    $key_017e = { 55 16 [2] 21 0e [2] 66 0c [2] 21 1d [2] 6f 11 [2] 63 1b [2] 74 10 [2] 6f 5e [2] 52 }

  condition:
    any of them
}