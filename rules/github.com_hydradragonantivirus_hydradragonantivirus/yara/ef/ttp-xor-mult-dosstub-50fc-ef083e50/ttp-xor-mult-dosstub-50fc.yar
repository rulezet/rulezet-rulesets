rule TTP_XOR_MULT_DOSStub_50fc {
  strings:
    $key_50fc = { 04 94 [2] 70 8c [2] 37 8e [2] 70 9f [2] 3e 93 [2] 32 99 [2] 25 92 [2] 3e dc [2] 03 }

  condition:
    any of them
}