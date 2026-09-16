rule TTP_XOR_WriteProcessMemory_2628 {
  strings:
    $key_2628 = { 71 5a [2] 43 78 [2] 45 4d [2] 6b 4d [2] 54 51 }

  condition:
    any of them
}