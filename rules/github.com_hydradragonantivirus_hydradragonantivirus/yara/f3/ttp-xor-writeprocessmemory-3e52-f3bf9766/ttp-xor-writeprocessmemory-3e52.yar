rule TTP_XOR_WriteProcessMemory_3e52 {
  strings:
    $key_3e52 = { 69 20 [2] 5b 02 [2] 5d 37 [2] 73 37 [2] 4c 2b }

  condition:
    any of them
}