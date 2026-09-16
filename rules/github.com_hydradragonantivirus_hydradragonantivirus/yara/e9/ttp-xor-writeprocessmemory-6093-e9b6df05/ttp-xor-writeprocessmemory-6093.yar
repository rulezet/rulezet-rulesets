rule TTP_XOR_WriteProcessMemory_6093 {
  strings:
    $key_6093 = { 37 e1 [2] 05 c3 [2] 03 f6 [2] 2d f6 [2] 12 ea }

  condition:
    any of them
}