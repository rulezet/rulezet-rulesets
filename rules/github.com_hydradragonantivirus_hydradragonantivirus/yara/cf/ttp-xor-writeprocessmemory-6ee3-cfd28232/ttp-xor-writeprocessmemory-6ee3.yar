rule TTP_XOR_WriteProcessMemory_6ee3 {
  strings:
    $key_6ee3 = { 39 91 [2] 0b b3 [2] 0d 86 [2] 23 86 [2] 1c 9a }

  condition:
    any of them
}