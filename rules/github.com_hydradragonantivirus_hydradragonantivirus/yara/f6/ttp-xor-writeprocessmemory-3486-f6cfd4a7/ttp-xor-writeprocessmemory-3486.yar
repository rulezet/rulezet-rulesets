rule TTP_XOR_WriteProcessMemory_3486 {
  strings:
    $key_3486 = { 63 f4 [2] 51 d6 [2] 57 e3 [2] 79 e3 [2] 46 ff }

  condition:
    any of them
}