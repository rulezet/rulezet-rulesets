rule TTP_XOR_MULT_DOSStub_5b3b {
  strings:
    $key_5b3b = { 0f 53 [2] 7b 4b [2] 3c 49 [2] 7b 58 [2] 35 54 [2] 39 5e [2] 2e 55 [2] 35 1b [2] 08 }

  condition:
    any of them
}