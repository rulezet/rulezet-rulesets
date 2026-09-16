rule TTP_XOR_WriteProcessMemory_594c {
  strings:
    $key_594c = { 0e 3e [2] 3c 1c [2] 3a 29 [2] 14 29 [2] 2b 35 }

  condition:
    any of them
}