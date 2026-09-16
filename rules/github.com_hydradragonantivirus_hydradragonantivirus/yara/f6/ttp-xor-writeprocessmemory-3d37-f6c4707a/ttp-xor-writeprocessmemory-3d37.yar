rule TTP_XOR_WriteProcessMemory_3d37 {
  strings:
    $key_3d37 = { 6a 45 [2] 58 67 [2] 5e 52 [2] 70 52 [2] 4f 4e }

  condition:
    any of them
}