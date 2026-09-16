rule TTP_XOR_MULT_DOSStub_393d {
  strings:
    $key_393d = { 6d 55 [2] 19 4d [2] 5e 4f [2] 19 5e [2] 57 52 [2] 5b 58 [2] 4c 53 [2] 57 1d [2] 6a }

  condition:
    any of them
}