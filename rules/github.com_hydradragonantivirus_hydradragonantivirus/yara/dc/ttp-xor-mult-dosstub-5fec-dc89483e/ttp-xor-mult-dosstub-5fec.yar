rule TTP_XOR_MULT_DOSStub_5fec {
  strings:
    $key_5fec = { 0b 84 [2] 7f 9c [2] 38 9e [2] 7f 8f [2] 31 83 [2] 3d 89 [2] 2a 82 [2] 31 cc [2] 0c }

  condition:
    any of them
}