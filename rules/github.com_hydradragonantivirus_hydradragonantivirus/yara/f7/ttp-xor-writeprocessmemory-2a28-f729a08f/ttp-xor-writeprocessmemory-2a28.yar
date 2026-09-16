rule TTP_XOR_WriteProcessMemory_2a28 {
  strings:
    $key_2a28 = { 7d 5a [2] 4f 78 [2] 49 4d [2] 67 4d [2] 58 51 }

  condition:
    any of them
}