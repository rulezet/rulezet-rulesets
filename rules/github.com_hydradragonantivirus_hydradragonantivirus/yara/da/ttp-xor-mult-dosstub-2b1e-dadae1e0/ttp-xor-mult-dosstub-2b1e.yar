rule TTP_XOR_MULT_DOSStub_2b1e {
  strings:
    $key_2b1e = { 7f 76 [2] 0b 6e [2] 4c 6c [2] 0b 7d [2] 45 71 [2] 49 7b [2] 5e 70 [2] 45 3e [2] 78 }

  condition:
    any of them
}