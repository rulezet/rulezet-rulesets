rule TTP_XOR_WriteProcessMemory_663d {
  strings:
    $key_663d = { 31 4f [2] 03 6d [2] 05 58 [2] 2b 58 [2] 14 44 }

  condition:
    any of them
}