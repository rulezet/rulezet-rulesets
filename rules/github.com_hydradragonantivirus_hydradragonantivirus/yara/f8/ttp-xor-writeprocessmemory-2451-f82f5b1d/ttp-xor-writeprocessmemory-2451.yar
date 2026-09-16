rule TTP_XOR_WriteProcessMemory_2451 {
  strings:
    $key_2451 = { 73 23 [2] 41 01 [2] 47 34 [2] 69 34 [2] 56 28 }

  condition:
    any of them
}