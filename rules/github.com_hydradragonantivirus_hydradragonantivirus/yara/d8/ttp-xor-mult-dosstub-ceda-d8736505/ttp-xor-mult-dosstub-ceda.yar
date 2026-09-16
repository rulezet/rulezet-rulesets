rule TTP_XOR_MULT_DOSStub_ceda {
  strings:
    $key_ceda = { 9a b2 [2] ee aa [2] a9 a8 [2] ee b9 [2] a0 b5 [2] ac bf [2] bb b4 [2] a0 fa [2] 9d }

  condition:
    any of them
}