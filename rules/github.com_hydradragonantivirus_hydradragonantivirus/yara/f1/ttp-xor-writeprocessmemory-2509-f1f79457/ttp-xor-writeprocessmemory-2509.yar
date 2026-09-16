rule TTP_XOR_WriteProcessMemory_2509 {
  strings:
    $key_2509 = { 72 7b [2] 40 59 [2] 46 6c [2] 68 6c [2] 57 70 }

  condition:
    any of them
}