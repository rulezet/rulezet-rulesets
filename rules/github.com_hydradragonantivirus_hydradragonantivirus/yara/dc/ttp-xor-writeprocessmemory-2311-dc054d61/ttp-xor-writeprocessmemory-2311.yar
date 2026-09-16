rule TTP_XOR_WriteProcessMemory_2311 {
  strings:
    $key_2311 = { 74 63 [2] 46 41 [2] 40 74 [2] 6e 74 [2] 51 68 }

  condition:
    any of them
}