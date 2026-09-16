rule TTP_XOR_WriteProcessMemory_4283 {
  strings:
    $key_4283 = { 15 f1 [2] 27 d3 [2] 21 e6 [2] 0f e6 [2] 30 fa }

  condition:
    any of them
}