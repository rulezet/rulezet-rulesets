rule TTP_XOR_MULT_DOSStub_a89d {
  strings:
    $key_a89d = { fc f5 [2] 88 ed [2] cf ef [2] 88 fe [2] c6 f2 [2] ca f8 [2] dd f3 [2] c6 bd [2] fb }

  condition:
    any of them
}