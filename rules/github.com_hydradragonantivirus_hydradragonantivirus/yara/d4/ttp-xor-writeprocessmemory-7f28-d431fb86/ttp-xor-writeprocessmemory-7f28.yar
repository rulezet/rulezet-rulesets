rule TTP_XOR_WriteProcessMemory_7f28 {
  strings:
    $key_7f28 = { 28 5a [2] 1a 78 [2] 1c 4d [2] 32 4d [2] 0d 51 }

  condition:
    any of them
}