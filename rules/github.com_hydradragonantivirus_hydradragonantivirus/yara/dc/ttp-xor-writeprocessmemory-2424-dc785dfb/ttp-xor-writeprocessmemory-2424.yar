rule TTP_XOR_WriteProcessMemory_2424 {
  strings:
    $key_2424 = { 73 56 [2] 41 74 [2] 47 41 [2] 69 41 [2] 56 5d }

  condition:
    any of them
}