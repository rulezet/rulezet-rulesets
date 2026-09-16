rule TTP_XOR_WriteProcessMemory_2ea8 {
  strings:
    $key_2ea8 = { 79 da [2] 4b f8 [2] 4d cd [2] 63 cd [2] 5c d1 }

  condition:
    any of them
}