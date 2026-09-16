rule TTP_XOR_WriteProcessMemory_7e35 {
  strings:
    $key_7e35 = { 29 47 [2] 1b 65 [2] 1d 50 [2] 33 50 [2] 0c 4c }

  condition:
    any of them
}