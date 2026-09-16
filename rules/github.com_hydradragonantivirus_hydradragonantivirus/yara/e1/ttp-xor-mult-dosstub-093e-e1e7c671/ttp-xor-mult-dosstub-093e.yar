rule TTP_XOR_MULT_DOSStub_093e {
  strings:
    $key_093e = { 5d 56 [2] 29 4e [2] 6e 4c [2] 29 5d [2] 67 51 [2] 6b 5b [2] 7c 50 [2] 67 1e [2] 5a }

  condition:
    any of them
}