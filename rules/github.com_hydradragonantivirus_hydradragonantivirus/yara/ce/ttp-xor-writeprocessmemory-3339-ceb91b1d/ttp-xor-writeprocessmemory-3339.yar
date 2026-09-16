rule TTP_XOR_WriteProcessMemory_3339 {
  strings:
    $key_3339 = { 64 4b [2] 56 69 [2] 50 5c [2] 7e 5c [2] 41 40 }

  condition:
    any of them
}