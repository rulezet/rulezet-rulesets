rule TTP_XOR_WriteProcessMemory_a583 {
  strings:
    $key_a583 = { f2 f1 [2] c0 d3 [2] c6 e6 [2] e8 e6 [2] d7 fa }

  condition:
    any of them
}