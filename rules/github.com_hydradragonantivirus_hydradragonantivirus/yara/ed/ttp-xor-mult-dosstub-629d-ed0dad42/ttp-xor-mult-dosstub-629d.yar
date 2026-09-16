rule TTP_XOR_MULT_DOSStub_629d {
  strings:
    $key_629d = { 36 f5 [2] 42 ed [2] 05 ef [2] 42 fe [2] 0c f2 [2] 00 f8 [2] 17 f3 [2] 0c bd [2] 31 }

  condition:
    any of them
}