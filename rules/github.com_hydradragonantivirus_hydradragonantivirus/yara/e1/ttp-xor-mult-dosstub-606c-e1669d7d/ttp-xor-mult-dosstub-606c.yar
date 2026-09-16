rule TTP_XOR_MULT_DOSStub_606c {
  strings:
    $key_606c = { 34 04 [2] 40 1c [2] 07 1e [2] 40 0f [2] 0e 03 [2] 02 09 [2] 15 02 [2] 0e 4c [2] 33 }

  condition:
    any of them
}