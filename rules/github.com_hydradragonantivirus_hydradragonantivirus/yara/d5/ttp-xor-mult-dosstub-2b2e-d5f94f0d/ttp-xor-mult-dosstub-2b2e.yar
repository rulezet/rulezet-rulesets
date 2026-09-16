rule TTP_XOR_MULT_DOSStub_2b2e {
  strings:
    $key_2b2e = { 7f 46 [2] 0b 5e [2] 4c 5c [2] 0b 4d [2] 45 41 [2] 49 4b [2] 5e 40 [2] 45 0e [2] 78 }

  condition:
    any of them
}