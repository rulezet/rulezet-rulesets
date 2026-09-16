rule TTP_XOR_MULT_DOSStub_02ec {
  strings:
    $key_02ec = { 56 84 [2] 22 9c [2] 65 9e [2] 22 8f [2] 6c 83 [2] 60 89 [2] 77 82 [2] 6c cc [2] 51 }

  condition:
    any of them
}