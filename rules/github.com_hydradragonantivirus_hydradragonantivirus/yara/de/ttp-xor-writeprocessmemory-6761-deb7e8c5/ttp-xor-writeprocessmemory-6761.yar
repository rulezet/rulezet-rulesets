rule TTP_XOR_WriteProcessMemory_6761 {
  strings:
    $key_6761 = { 30 13 [2] 02 31 [2] 04 04 [2] 2a 04 [2] 15 18 }

  condition:
    any of them
}