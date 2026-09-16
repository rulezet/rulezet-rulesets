rule TTP_XOR_WriteProcessMemory_3d83 {
  strings:
    $key_3d83 = { 6a f1 [2] 58 d3 [2] 5e e6 [2] 70 e6 [2] 4f fa }

  condition:
    any of them
}