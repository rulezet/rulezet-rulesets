rule TTP_XOR_MULT_DOSStub_072c {
  strings:
    $key_072c = { 53 44 [2] 27 5c [2] 60 5e [2] 27 4f [2] 69 43 [2] 65 49 [2] 72 42 [2] 69 0c [2] 54 }

  condition:
    any of them
}