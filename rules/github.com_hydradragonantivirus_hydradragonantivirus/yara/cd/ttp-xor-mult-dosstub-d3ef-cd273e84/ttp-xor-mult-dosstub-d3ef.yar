rule TTP_XOR_MULT_DOSStub_d3ef {
  strings:
    $key_d3ef = { 87 87 [2] f3 9f [2] b4 9d [2] f3 8c [2] bd 80 [2] b1 8a [2] a6 81 [2] bd cf [2] 80 }

  condition:
    any of them
}