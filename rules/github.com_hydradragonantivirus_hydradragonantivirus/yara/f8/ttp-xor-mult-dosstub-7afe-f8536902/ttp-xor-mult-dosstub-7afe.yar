rule TTP_XOR_MULT_DOSStub_7afe {
  strings:
    $key_7afe = { 2e 96 [2] 5a 8e [2] 1d 8c [2] 5a 9d [2] 14 91 [2] 18 9b [2] 0f 90 [2] 14 de [2] 29 }

  condition:
    any of them
}