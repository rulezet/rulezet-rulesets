rule TTP_XOR_WriteProcessMemory_2fcc {
  strings:
    $key_2fcc = { 78 be [2] 4a 9c [2] 4c a9 [2] 62 a9 [2] 5d b5 }

  condition:
    any of them
}