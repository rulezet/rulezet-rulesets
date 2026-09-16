rule TTP_XOR_WriteProcessMemory_2e0d {
  strings:
    $key_2e0d = { 79 7f [2] 4b 5d [2] 4d 68 [2] 63 68 [2] 5c 74 }

  condition:
    any of them
}