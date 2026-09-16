rule TTP_XOR_WriteProcessMemory_0b38 {
  strings:
    $key_0b38 = { 5c 4a [2] 6e 68 [2] 68 5d [2] 46 5d [2] 79 41 }

  condition:
    any of them
}