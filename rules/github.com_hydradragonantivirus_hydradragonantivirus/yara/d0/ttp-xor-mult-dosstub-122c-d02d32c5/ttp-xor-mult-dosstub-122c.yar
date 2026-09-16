rule TTP_XOR_MULT_DOSStub_122c {
  strings:
    $key_122c = { 46 44 [2] 32 5c [2] 75 5e [2] 32 4f [2] 7c 43 [2] 70 49 [2] 67 42 [2] 7c 0c [2] 41 }

  condition:
    any of them
}