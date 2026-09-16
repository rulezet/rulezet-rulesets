rule TTP_XOR_WriteProcessMemory_1ee3 {
  strings:
    $key_1ee3 = { 49 91 [2] 7b b3 [2] 7d 86 [2] 53 86 [2] 6c 9a }

  condition:
    any of them
}