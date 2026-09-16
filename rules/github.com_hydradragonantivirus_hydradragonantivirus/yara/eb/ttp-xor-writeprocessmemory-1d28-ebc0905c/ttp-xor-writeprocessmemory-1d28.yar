rule TTP_XOR_WriteProcessMemory_1d28 {
  strings:
    $key_1d28 = { 4a 5a [2] 78 78 [2] 7e 4d [2] 50 4d [2] 6f 51 }

  condition:
    any of them
}