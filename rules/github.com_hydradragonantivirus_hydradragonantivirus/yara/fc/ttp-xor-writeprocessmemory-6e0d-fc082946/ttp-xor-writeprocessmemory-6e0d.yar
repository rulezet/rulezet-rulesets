rule TTP_XOR_WriteProcessMemory_6e0d {
  strings:
    $key_6e0d = { 39 7f [2] 0b 5d [2] 0d 68 [2] 23 68 [2] 1c 74 }

  condition:
    any of them
}