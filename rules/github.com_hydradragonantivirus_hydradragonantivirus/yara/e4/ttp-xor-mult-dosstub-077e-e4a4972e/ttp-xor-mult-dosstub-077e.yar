rule TTP_XOR_MULT_DOSStub_077e {
  strings:
    $key_077e = { 53 16 [2] 27 0e [2] 60 0c [2] 27 1d [2] 69 11 [2] 65 1b [2] 72 10 [2] 69 5e [2] 54 }

  condition:
    any of them
}