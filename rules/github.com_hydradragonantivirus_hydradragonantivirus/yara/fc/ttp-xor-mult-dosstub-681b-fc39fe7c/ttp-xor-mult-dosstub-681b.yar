rule TTP_XOR_MULT_DOSStub_681b {
  strings:
    $key_681b = { 3c 73 [2] 48 6b [2] 0f 69 [2] 48 78 [2] 06 74 [2] 0a 7e [2] 1d 75 [2] 06 3b [2] 3b }

  condition:
    any of them
}