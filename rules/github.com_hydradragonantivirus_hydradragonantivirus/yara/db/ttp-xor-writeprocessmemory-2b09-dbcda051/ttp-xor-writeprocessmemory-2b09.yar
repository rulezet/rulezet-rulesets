rule TTP_XOR_WriteProcessMemory_2b09 {
  strings:
    $key_2b09 = { 7c 7b [2] 4e 59 [2] 48 6c [2] 66 6c [2] 59 70 }

  condition:
    any of them
}