rule TTP_XOR_WriteProcessMemory_3e20 {
  strings:
    $key_3e20 = { 69 52 [2] 5b 70 [2] 5d 45 [2] 73 45 [2] 4c 59 }

  condition:
    any of them
}