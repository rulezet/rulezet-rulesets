rule TTP_XOR_WriteProcessMemory_3e41 {
  strings:
    $key_3e41 = { 69 33 [2] 5b 11 [2] 5d 24 [2] 73 24 [2] 4c 38 }

  condition:
    any of them
}