rule TTP_XOR_MULT_DOSStub_202b {
  strings:
    $key_202b = { 74 43 [2] 00 5b [2] 47 59 [2] 00 48 [2] 4e 44 [2] 42 4e [2] 55 45 [2] 4e 0b [2] 73 }

  condition:
    any of them
}