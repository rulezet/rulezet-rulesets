rule TTP_XOR_WriteProcessMemory_3e35 {
  strings:
    $key_3e35 = { 69 47 [2] 5b 65 [2] 5d 50 [2] 73 50 [2] 4c 4c }

  condition:
    any of them
}