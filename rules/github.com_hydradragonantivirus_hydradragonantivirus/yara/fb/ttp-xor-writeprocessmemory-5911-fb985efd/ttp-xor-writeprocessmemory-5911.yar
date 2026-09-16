rule TTP_XOR_WriteProcessMemory_5911 {
  strings:
    $key_5911 = { 0e 63 [2] 3c 41 [2] 3a 74 [2] 14 74 [2] 2b 68 }

  condition:
    any of them
}