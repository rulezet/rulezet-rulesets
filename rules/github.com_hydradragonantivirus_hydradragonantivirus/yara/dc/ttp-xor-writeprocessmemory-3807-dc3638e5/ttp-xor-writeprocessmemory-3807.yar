rule TTP_XOR_WriteProcessMemory_3807 {
  strings:
    $key_3807 = { 6f 75 [2] 5d 57 [2] 5b 62 [2] 75 62 [2] 4a 7e }

  condition:
    any of them
}