rule TTP_XOR_WriteProcessMemory_5a0d {
  strings:
    $key_5a0d = { 0d 7f [2] 3f 5d [2] 39 68 [2] 17 68 [2] 28 74 }

  condition:
    any of them
}