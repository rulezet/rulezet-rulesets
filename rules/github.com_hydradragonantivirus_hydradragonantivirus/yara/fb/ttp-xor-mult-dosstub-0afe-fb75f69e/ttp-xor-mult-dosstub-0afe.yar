rule TTP_XOR_MULT_DOSStub_0afe {
  strings:
    $key_0afe = { 5e 96 [2] 2a 8e [2] 6d 8c [2] 2a 9d [2] 64 91 [2] 68 9b [2] 7f 90 [2] 64 de [2] 59 }

  condition:
    any of them
}