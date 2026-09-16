rule TTP_XOR_WriteProcessMemory_3e30 {
  strings:
    $key_3e30 = { 69 42 [2] 5b 60 [2] 5d 55 [2] 73 55 [2] 4c 49 }

  condition:
    any of them
}