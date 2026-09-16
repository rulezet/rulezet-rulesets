rule TTP_XOR_WriteProcessMemory_201a {
  strings:
    $key_201a = { 77 68 [2] 45 4a [2] 43 7f [2] 6d 7f [2] 52 63 }

  condition:
    any of them
}