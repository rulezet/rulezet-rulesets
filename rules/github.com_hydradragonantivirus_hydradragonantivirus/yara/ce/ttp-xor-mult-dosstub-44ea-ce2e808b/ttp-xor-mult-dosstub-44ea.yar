rule TTP_XOR_MULT_DOSStub_44ea {
  strings:
    $key_44ea = { 10 82 [2] 64 9a [2] 23 98 [2] 64 89 [2] 2a 85 [2] 26 8f [2] 31 84 [2] 2a ca [2] 17 }

  condition:
    any of them
}