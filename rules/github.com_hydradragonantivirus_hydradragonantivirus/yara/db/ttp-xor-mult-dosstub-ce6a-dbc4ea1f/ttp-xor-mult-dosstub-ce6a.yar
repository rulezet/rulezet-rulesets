rule TTP_XOR_MULT_DOSStub_ce6a {
  strings:
    $key_ce6a = { 9a 02 [2] ee 1a [2] a9 18 [2] ee 09 [2] a0 05 [2] ac 0f [2] bb 04 [2] a0 4a [2] 9d }

  condition:
    any of them
}