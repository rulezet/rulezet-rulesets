rule TTP_XOR_MULT_DOSStub_3866 {
  strings:
    $key_3866 = { 6c 0e [2] 18 16 [2] 5f 14 [2] 18 05 [2] 56 09 [2] 5a 03 [2] 4d 08 [2] 56 46 [2] 6b }

  condition:
    any of them
}