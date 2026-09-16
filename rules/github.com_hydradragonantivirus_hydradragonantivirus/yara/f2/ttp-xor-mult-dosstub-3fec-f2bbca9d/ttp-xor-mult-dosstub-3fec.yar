rule TTP_XOR_MULT_DOSStub_3fec {
  strings:
    $key_3fec = { 6b 84 [2] 1f 9c [2] 58 9e [2] 1f 8f [2] 51 83 [2] 5d 89 [2] 4a 82 [2] 51 cc [2] 6c }

  condition:
    any of them
}