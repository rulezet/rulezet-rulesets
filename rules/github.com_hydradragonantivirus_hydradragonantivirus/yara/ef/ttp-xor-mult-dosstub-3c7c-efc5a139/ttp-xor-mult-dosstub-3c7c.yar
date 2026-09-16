rule TTP_XOR_MULT_DOSStub_3c7c {
  strings:
    $key_3c7c = { 68 14 [2] 1c 0c [2] 5b 0e [2] 1c 1f [2] 52 13 [2] 5e 19 [2] 49 12 [2] 52 5c [2] 6f }

  condition:
    any of them
}