rule TTP_XOR_MULT_DOSStub_393e {
  strings:
    $key_393e = { 6d 56 [2] 19 4e [2] 5e 4c [2] 19 5d [2] 57 51 [2] 5b 5b [2] 4c 50 [2] 57 1e [2] 6a }

  condition:
    any of them
}