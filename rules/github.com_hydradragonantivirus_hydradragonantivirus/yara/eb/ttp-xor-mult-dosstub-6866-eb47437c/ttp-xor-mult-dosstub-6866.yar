rule TTP_XOR_MULT_DOSStub_6866 {
  strings:
    $key_6866 = { 3c 0e [2] 48 16 [2] 0f 14 [2] 48 05 [2] 06 09 [2] 0a 03 [2] 1d 08 [2] 06 46 [2] 3b }

  condition:
    any of them
}