rule TTP_XOR_WriteProcessMemory_ada7 {
  strings:
    $key_ada7 = { fa d5 [2] c8 f7 [2] ce c2 [2] e0 c2 [2] df de }

  condition:
    any of them
}