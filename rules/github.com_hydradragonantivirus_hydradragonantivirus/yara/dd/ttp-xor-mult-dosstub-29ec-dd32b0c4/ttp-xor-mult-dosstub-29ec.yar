rule TTP_XOR_MULT_DOSStub_29ec {
  strings:
    $key_29ec = { 7d 84 [2] 09 9c [2] 4e 9e [2] 09 8f [2] 47 83 [2] 4b 89 [2] 5c 82 [2] 47 cc [2] 7a }

  condition:
    any of them
}