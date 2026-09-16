rule TTP_XOR_MULT_DOSStub_dfdc {
  strings:
    $key_dfdc = { 8b b4 [2] ff ac [2] b8 ae [2] ff bf [2] b1 b3 [2] bd b9 [2] aa b2 [2] b1 fc [2] 8c }

  condition:
    any of them
}