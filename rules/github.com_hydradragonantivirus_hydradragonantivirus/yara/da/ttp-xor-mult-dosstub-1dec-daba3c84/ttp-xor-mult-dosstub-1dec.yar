rule TTP_XOR_MULT_DOSStub_1dec {
  strings:
    $key_1dec = { 49 84 [2] 3d 9c [2] 7a 9e [2] 3d 8f [2] 73 83 [2] 7f 89 [2] 68 82 [2] 73 cc [2] 4e }

  condition:
    any of them
}