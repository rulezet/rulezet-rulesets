rule TTP_XOR_MULT_DOSStub_08fc {
  strings:
    $key_08fc = { 5c 94 [2] 28 8c [2] 6f 8e [2] 28 9f [2] 66 93 [2] 6a 99 [2] 7d 92 [2] 66 dc [2] 5b }

  condition:
    any of them
}