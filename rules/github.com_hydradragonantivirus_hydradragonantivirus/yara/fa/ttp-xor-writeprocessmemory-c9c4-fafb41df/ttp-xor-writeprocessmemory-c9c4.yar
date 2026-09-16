rule TTP_XOR_WriteProcessMemory_c9c4 {
  strings:
    $key_c9c4 = { 9e b6 [2] ac 94 [2] aa a1 [2] 84 a1 [2] bb bd }

  condition:
    any of them
}