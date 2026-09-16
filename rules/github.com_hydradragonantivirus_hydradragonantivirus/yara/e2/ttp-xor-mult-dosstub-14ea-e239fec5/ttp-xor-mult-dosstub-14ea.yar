rule TTP_XOR_MULT_DOSStub_14ea {
  strings:
    $key_14ea = { 40 82 [2] 34 9a [2] 73 98 [2] 34 89 [2] 7a 85 [2] 76 8f [2] 61 84 [2] 7a ca [2] 47 }

  condition:
    any of them
}