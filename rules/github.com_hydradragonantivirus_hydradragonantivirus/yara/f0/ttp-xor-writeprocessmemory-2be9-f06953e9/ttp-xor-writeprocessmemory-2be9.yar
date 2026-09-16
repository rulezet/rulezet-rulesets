rule TTP_XOR_WriteProcessMemory_2be9 {
  strings:
    $key_2be9 = { 7c 9b [2] 4e b9 [2] 48 8c [2] 66 8c [2] 59 90 }

  condition:
    any of them
}