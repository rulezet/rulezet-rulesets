rule TTP_XOR_WriteProcessMemory_2979 {
  strings:
    $key_2979 = { 7e 0b [2] 4c 29 [2] 4a 1c [2] 64 1c [2] 5b 00 }

  condition:
    any of them
}