rule TTP_XOR_WriteProcessMemory_6828 {
  strings:
    $key_6828 = { 3f 5a [2] 0d 78 [2] 0b 4d [2] 25 4d [2] 1a 51 }

  condition:
    any of them
}