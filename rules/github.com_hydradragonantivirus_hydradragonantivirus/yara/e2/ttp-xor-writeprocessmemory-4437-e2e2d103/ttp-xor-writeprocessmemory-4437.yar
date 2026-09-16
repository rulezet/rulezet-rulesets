rule TTP_XOR_WriteProcessMemory_4437 {
  strings:
    $key_4437 = { 13 45 [2] 21 67 [2] 27 52 [2] 09 52 [2] 36 4e }

  condition:
    any of them
}