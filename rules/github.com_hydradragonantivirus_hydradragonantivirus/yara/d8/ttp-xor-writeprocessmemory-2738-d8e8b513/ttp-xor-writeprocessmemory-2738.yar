rule TTP_XOR_WriteProcessMemory_2738 {
  strings:
    $key_2738 = { 70 4a [2] 42 68 [2] 44 5d [2] 6a 5d [2] 55 41 }

  condition:
    any of them
}