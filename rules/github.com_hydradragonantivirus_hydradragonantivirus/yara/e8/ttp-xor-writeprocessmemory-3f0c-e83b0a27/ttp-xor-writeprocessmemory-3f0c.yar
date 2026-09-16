rule TTP_XOR_WriteProcessMemory_3f0c {
  strings:
    $key_3f0c = { 68 7e [2] 5a 5c [2] 5c 69 [2] 72 69 [2] 4d 75 }

  condition:
    any of them
}