rule TTP_XOR_MULT_DOSStub_393a {
  strings:
    $key_393a = { 6d 52 [2] 19 4a [2] 5e 48 [2] 19 59 [2] 57 55 [2] 5b 5f [2] 4c 54 [2] 57 1a [2] 6a }

  condition:
    any of them
}