rule TTP_XOR_WriteProcessMemory_240d {
  strings:
    $key_240d = { 73 7f [2] 41 5d [2] 47 68 [2] 69 68 [2] 56 74 }

  condition:
    any of them
}