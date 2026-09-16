rule TTP_XOR_MULT_DOSStub_bdbc {
  strings:
    $key_bdbc = { e9 d4 [2] 9d cc [2] da ce [2] 9d df [2] d3 d3 [2] df d9 [2] c8 d2 [2] d3 9c [2] ee }

  condition:
    any of them
}