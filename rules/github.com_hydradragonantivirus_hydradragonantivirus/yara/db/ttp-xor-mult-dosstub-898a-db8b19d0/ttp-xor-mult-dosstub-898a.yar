rule TTP_XOR_MULT_DOSStub_898a {
  strings:
    $key_898a = { dd e2 [2] a9 fa [2] ee f8 [2] a9 e9 [2] e7 e5 [2] eb ef [2] fc e4 [2] e7 aa [2] da }

  condition:
    any of them
}