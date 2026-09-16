rule TTP_XOR_MULT_DOSStub_5b2b {
  strings:
    $key_5b2b = { 0f 43 [2] 7b 5b [2] 3c 59 [2] 7b 48 [2] 35 44 [2] 39 4e [2] 2e 45 [2] 35 0b [2] 08 }

  condition:
    any of them
}