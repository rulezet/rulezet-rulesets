rule TTP_XOR_WriteProcessMemory_2943 {
  strings:
    $key_2943 = { 7e 31 [2] 4c 13 [2] 4a 26 [2] 64 26 [2] 5b 3a }

  condition:
    any of them
}