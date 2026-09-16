rule TTP_XOR_WriteProcessMemory_0610 {
  strings:
    $key_0610 = { 51 62 [2] 63 40 [2] 65 75 [2] 4b 75 [2] 74 69 }

  condition:
    any of them
}