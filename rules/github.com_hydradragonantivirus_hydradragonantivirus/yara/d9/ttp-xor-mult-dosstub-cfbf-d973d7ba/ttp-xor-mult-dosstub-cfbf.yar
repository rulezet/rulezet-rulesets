rule TTP_XOR_MULT_DOSStub_cfbf {
  strings:
    $key_cfbf = { 9b d7 [2] ef cf [2] a8 cd [2] ef dc [2] a1 d0 [2] ad da [2] ba d1 [2] a1 9f [2] 9c }

  condition:
    any of them
}