rule TTP_XOR_WriteProcessMemory_7628 {
  strings:
    $key_7628 = { 21 5a [2] 13 78 [2] 15 4d [2] 3b 4d [2] 04 51 }

  condition:
    any of them
}