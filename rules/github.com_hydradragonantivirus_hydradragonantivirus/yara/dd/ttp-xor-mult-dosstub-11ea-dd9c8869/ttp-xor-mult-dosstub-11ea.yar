rule TTP_XOR_MULT_DOSStub_11ea {
  strings:
    $key_11ea = { 45 82 [2] 31 9a [2] 76 98 [2] 31 89 [2] 7f 85 [2] 73 8f [2] 64 84 [2] 7f ca [2] 42 }

  condition:
    any of them
}