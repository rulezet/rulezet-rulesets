rule TTP_XOR_MULT_DOSStub_ce6c {
  strings:
    $key_ce6c = { 9a 04 [2] ee 1c [2] a9 1e [2] ee 0f [2] a0 03 [2] ac 09 [2] bb 02 [2] a0 4c [2] 9d }

  condition:
    any of them
}