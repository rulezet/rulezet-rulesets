rule TTP_XOR_WriteProcessMemory_080d {
  strings:
    $key_080d = { 5f 7f [2] 6d 5d [2] 6b 68 [2] 45 68 [2] 7a 74 }

  condition:
    any of them
}