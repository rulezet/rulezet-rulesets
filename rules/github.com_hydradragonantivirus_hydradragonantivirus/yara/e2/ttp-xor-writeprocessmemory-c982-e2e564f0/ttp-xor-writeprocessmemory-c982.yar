rule TTP_XOR_WriteProcessMemory_c982 {
  strings:
    $key_c982 = { 9e f0 [2] ac d2 [2] aa e7 [2] 84 e7 [2] bb fb }

  condition:
    any of them
}