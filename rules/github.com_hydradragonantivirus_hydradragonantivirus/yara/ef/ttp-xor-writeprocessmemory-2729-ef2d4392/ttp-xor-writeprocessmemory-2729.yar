rule TTP_XOR_WriteProcessMemory_2729 {
  strings:
    $key_2729 = { 70 5b [2] 42 79 [2] 44 4c [2] 6a 4c [2] 55 50 }

  condition:
    any of them
}