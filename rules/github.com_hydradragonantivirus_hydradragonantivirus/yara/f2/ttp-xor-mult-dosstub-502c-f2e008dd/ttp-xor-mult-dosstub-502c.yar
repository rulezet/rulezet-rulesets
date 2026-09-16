rule TTP_XOR_MULT_DOSStub_502c {
  strings:
    $key_502c = { 04 44 [2] 70 5c [2] 37 5e [2] 70 4f [2] 3e 43 [2] 32 49 [2] 25 42 [2] 3e 0c [2] 03 }

  condition:
    any of them
}