rule TTP_XOR_MULT_DOSStub_50fe {
  strings:
    $key_50fe = { 04 96 [2] 70 8e [2] 37 8c [2] 70 9d [2] 3e 91 [2] 32 9b [2] 25 90 [2] 3e de [2] 03 }

  condition:
    any of them
}