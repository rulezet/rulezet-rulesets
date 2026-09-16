rule TTP_XOR_MULT_DOSStub_259d {
  strings:
    $key_259d = { 71 f5 [2] 05 ed [2] 42 ef [2] 05 fe [2] 4b f2 [2] 47 f8 [2] 50 f3 [2] 4b bd [2] 76 }

  condition:
    any of them
}