rule TTP_XOR_MULT_DOSStub_09ec {
  strings:
    $key_09ec = { 5d 84 [2] 29 9c [2] 6e 9e [2] 29 8f [2] 67 83 [2] 6b 89 [2] 7c 82 [2] 67 cc [2] 5a }

  condition:
    any of them
}