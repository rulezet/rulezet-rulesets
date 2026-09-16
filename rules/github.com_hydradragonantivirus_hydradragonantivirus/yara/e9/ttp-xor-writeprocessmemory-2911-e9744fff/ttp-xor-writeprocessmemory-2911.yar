rule TTP_XOR_WriteProcessMemory_2911 {
  strings:
    $key_2911 = { 7e 63 [2] 4c 41 [2] 4a 74 [2] 64 74 [2] 5b 68 }

  condition:
    any of them
}