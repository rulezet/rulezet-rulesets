rule TTP_XOR_WriteProcessMemory_2507 {
  strings:
    $key_2507 = { 72 75 [2] 40 57 [2] 46 62 [2] 68 62 [2] 57 7e }

  condition:
    any of them
}