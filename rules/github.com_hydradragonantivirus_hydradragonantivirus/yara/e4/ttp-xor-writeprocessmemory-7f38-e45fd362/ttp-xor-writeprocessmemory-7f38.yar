rule TTP_XOR_WriteProcessMemory_7f38 {
  strings:
    $key_7f38 = { 28 4a [2] 1a 68 [2] 1c 5d [2] 32 5d [2] 0d 41 }

  condition:
    any of them
}