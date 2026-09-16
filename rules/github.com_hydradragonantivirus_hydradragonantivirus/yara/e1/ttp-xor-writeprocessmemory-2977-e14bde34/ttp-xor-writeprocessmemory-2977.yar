rule TTP_XOR_WriteProcessMemory_2977 {
  strings:
    $key_2977 = { 7e 05 [2] 4c 27 [2] 4a 12 [2] 64 12 [2] 5b 0e }

  condition:
    any of them
}