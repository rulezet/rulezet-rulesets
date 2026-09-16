rule TTP_XOR_MULT_DOSStub_3afe {
  strings:
    $key_3afe = { 6e 96 [2] 1a 8e [2] 5d 8c [2] 1a 9d [2] 54 91 [2] 58 9b [2] 4f 90 [2] 54 de [2] 69 }

  condition:
    any of them
}