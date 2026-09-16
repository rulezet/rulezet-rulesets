rule TTP_XOR_WriteProcessMemory_1ae3 {
  strings:
    $key_1ae3 = { 4d 91 [2] 7f b3 [2] 79 86 [2] 57 86 [2] 68 9a }

  condition:
    any of them
}