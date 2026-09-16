rule TTP_XOR_WriteProcessMemory_1938 {
  strings:
    $key_1938 = { 4e 4a [2] 7c 68 [2] 7a 5d [2] 54 5d [2] 6b 41 }

  condition:
    any of them
}