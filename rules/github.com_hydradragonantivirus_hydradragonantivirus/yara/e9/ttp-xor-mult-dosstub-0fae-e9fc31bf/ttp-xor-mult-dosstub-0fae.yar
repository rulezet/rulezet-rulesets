rule TTP_XOR_MULT_DOSStub_0fae {
  strings:
    $key_0fae = { 5b c6 [2] 2f de [2] 68 dc [2] 2f cd [2] 61 c1 [2] 6d cb [2] 7a c0 [2] 61 8e [2] 5c }

  condition:
    any of them
}