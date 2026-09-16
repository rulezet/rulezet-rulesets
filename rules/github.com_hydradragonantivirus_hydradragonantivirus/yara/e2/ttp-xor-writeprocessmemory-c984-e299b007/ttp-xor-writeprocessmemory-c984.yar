rule TTP_XOR_WriteProcessMemory_c984 {
  strings:
    $key_c984 = { 9e f6 [2] ac d4 [2] aa e1 [2] 84 e1 [2] bb fd }

  condition:
    any of them
}