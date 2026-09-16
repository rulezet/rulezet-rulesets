rule TTP_XOR_WriteProcessMemory_0a38 {
  strings:
    $key_0a38 = { 5d 4a [2] 6f 68 [2] 69 5d [2] 47 5d [2] 78 41 }

  condition:
    any of them
}