rule TTP_XOR_WriteProcessMemory_3e0c {
  strings:
    $key_3e0c = { 69 7e [2] 5b 5c [2] 5d 69 [2] 73 69 [2] 4c 75 }

  condition:
    any of them
}