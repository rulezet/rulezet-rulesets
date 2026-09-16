rule TTP_XOR_WriteProcessMemory_3e31 {
  strings:
    $key_3e31 = { 69 43 [2] 5b 61 [2] 5d 54 [2] 73 54 [2] 4c 48 }

  condition:
    any of them
}