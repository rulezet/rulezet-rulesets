rule TTP_XOR_WriteProcessMemory_2952 {
  strings:
    $key_2952 = { 7e 20 [2] 4c 02 [2] 4a 37 [2] 64 37 [2] 5b 2b }

  condition:
    any of them
}