rule TTP_XOR_MULT_DOSStub_f893 {
  strings:
    $key_f893 = { ac fb [2] d8 e3 [2] 9f e1 [2] d8 f0 [2] 96 fc [2] 9a f6 [2] 8d fd [2] 96 b3 [2] ab }

  condition:
    any of them
}