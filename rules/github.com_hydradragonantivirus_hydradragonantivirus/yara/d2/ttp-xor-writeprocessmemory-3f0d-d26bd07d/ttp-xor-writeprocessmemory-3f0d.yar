rule TTP_XOR_WriteProcessMemory_3f0d {
  strings:
    $key_3f0d = { 68 7f [2] 5a 5d [2] 5c 68 [2] 72 68 [2] 4d 74 }

  condition:
    any of them
}