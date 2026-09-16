rule TTP_XOR_MULT_DOSStub_dfbb {
  strings:
    $key_dfbb = { 8b d3 [2] ff cb [2] b8 c9 [2] ff d8 [2] b1 d4 [2] bd de [2] aa d5 [2] b1 9b [2] 8c }

  condition:
    any of them
}