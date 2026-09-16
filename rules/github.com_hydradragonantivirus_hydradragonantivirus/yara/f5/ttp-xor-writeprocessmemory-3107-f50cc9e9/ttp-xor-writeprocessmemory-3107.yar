rule TTP_XOR_WriteProcessMemory_3107 {
  strings:
    $key_3107 = { 66 75 [2] 54 57 [2] 52 62 [2] 7c 62 [2] 43 7e }

  condition:
    any of them
}