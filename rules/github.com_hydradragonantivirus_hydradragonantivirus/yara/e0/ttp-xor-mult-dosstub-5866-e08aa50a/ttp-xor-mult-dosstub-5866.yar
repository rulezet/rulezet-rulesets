rule TTP_XOR_MULT_DOSStub_5866 {
  strings:
    $key_5866 = { 0c 0e [2] 78 16 [2] 3f 14 [2] 78 05 [2] 36 09 [2] 3a 03 [2] 2d 08 [2] 36 46 [2] 0b }

  condition:
    any of them
}