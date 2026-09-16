rule TTP_XOR_WriteProcessMemory_ab83 {
  strings:
    $key_ab83 = { fc f1 [2] ce d3 [2] c8 e6 [2] e6 e6 [2] d9 fa }

  condition:
    any of them
}