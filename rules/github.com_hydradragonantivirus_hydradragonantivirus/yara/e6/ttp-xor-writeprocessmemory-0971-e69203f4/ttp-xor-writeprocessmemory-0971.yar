rule TTP_XOR_WriteProcessMemory_0971 {
  strings:
    $key_0971 = { 5e 03 [2] 6c 21 [2] 6a 14 [2] 44 14 [2] 7b 08 }

  condition:
    any of them
}