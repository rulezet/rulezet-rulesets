rule TTP_XOR_MULT_DOSStub_2fec {
  strings:
    $key_2fec = { 7b 84 [2] 0f 9c [2] 48 9e [2] 0f 8f [2] 41 83 [2] 4d 89 [2] 5a 82 [2] 41 cc [2] 7c }

  condition:
    any of them
}