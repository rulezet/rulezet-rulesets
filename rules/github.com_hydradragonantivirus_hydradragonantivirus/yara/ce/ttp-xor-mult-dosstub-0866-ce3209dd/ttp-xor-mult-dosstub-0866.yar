rule TTP_XOR_MULT_DOSStub_0866 {
  strings:
    $key_0866 = { 5c 0e [2] 28 16 [2] 6f 14 [2] 28 05 [2] 66 09 [2] 6a 03 [2] 7d 08 [2] 66 46 [2] 5b }

  condition:
    any of them
}