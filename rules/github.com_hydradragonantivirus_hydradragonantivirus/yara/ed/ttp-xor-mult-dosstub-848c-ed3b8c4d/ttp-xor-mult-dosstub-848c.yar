rule TTP_XOR_MULT_DOSStub_848c {
  strings:
    $key_848c = { d0 e4 [2] a4 fc [2] e3 fe [2] a4 ef [2] ea e3 [2] e6 e9 [2] f1 e2 [2] ea ac [2] d7 }

  condition:
    any of them
}