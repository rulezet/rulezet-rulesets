rule TTP_XOR_MULT_DOSStub_5c4c {
  strings:
    $key_5c4c = { 08 24 [2] 7c 3c [2] 3b 3e [2] 7c 2f [2] 32 23 [2] 3e 29 [2] 29 22 [2] 32 6c [2] 0f }

  condition:
    any of them
}