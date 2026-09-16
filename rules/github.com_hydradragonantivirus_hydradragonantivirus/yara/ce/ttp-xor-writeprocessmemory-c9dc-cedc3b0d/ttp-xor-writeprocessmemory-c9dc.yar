rule TTP_XOR_WriteProcessMemory_c9dc {
  strings:
    $key_c9dc = { 9e ae [2] ac 8c [2] aa b9 [2] 84 b9 [2] bb a5 }

  condition:
    any of them
}