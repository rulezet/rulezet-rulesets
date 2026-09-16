rule TTP_XOR_MULT_DOSStub_393f {
  strings:
    $key_393f = { 6d 57 [2] 19 4f [2] 5e 4d [2] 19 5c [2] 57 50 [2] 5b 5a [2] 4c 51 [2] 57 1f [2] 6a }

  condition:
    any of them
}