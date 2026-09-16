rule TTP_XOR_MULT_DOSStub_06fc {
  strings:
    $key_06fc = { 52 94 [2] 26 8c [2] 61 8e [2] 26 9f [2] 68 93 [2] 64 99 [2] 73 92 [2] 68 dc [2] 55 }

  condition:
    any of them
}