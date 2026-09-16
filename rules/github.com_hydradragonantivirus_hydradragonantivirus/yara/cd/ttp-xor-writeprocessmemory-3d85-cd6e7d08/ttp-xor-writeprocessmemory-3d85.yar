rule TTP_XOR_WriteProcessMemory_3d85 {
  strings:
    $key_3d85 = { 6a f7 [2] 58 d5 [2] 5e e0 [2] 70 e0 [2] 4f fc }

  condition:
    any of them
}