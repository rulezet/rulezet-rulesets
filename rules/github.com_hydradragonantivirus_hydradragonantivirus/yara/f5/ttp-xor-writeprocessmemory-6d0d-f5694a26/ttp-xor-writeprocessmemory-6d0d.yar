rule TTP_XOR_WriteProcessMemory_6d0d {
  strings:
    $key_6d0d = { 3a 7f [2] 08 5d [2] 0e 68 [2] 20 68 [2] 1f 74 }

  condition:
    any of them
}