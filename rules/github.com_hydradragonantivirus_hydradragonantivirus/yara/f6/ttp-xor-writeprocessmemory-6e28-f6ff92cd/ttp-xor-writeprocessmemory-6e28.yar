rule TTP_XOR_WriteProcessMemory_6e28 {
  strings:
    $key_6e28 = { 39 5a [2] 0b 78 [2] 0d 4d [2] 23 4d [2] 1c 51 }

  condition:
    any of them
}