rule TTP_XOR_MULT_DOSStub_ce88 {
  strings:
    $key_ce88 = { 9a e0 [2] ee f8 [2] a9 fa [2] ee eb [2] a0 e7 [2] ac ed [2] bb e6 [2] a0 a8 [2] 9d }

  condition:
    any of them
}