rule TTP_XOR_WriteProcessMemory_2a38 {
  strings:
    $key_2a38 = { 7d 4a [2] 4f 68 [2] 49 5d [2] 67 5d [2] 58 41 }

  condition:
    any of them
}