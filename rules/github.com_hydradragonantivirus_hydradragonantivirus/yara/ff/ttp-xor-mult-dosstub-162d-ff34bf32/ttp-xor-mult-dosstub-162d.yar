rule TTP_XOR_MULT_DOSStub_162d {
  strings:
    $key_162d = { 42 45 [2] 36 5d [2] 71 5f [2] 36 4e [2] 78 42 [2] 74 48 [2] 63 43 [2] 78 0d [2] 45 }

  condition:
    any of them
}