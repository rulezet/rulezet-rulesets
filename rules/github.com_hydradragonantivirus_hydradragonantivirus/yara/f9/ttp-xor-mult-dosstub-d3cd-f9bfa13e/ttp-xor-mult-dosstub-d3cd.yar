rule TTP_XOR_MULT_DOSStub_d3cd {
  strings:
    $key_d3cd = { 87 a5 [2] f3 bd [2] b4 bf [2] f3 ae [2] bd a2 [2] b1 a8 [2] a6 a3 [2] bd ed [2] 80 }

  condition:
    any of them
}