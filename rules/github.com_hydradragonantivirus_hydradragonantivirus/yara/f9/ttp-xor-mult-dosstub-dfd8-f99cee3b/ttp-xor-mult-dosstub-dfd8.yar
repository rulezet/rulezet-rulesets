rule TTP_XOR_MULT_DOSStub_dfd8 {
  strings:
    $key_dfd8 = { 8b b0 [2] ff a8 [2] b8 aa [2] ff bb [2] b1 b7 [2] bd bd [2] aa b6 [2] b1 f8 [2] 8c }

  condition:
    any of them
}