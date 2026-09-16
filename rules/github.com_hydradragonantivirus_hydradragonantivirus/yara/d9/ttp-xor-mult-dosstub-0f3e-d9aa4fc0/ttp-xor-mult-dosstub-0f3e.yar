rule TTP_XOR_MULT_DOSStub_0f3e {
  strings:
    $key_0f3e = { 5b 56 [2] 2f 4e [2] 68 4c [2] 2f 5d [2] 61 51 [2] 6d 5b [2] 7a 50 [2] 61 1e [2] 5c }

  condition:
    any of them
}