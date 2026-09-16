rule TTP_XOR_WriteProcessMemory_0952 {
  strings:
    $key_0952 = { 5e 20 [2] 6c 02 [2] 6a 37 [2] 44 37 [2] 7b 2b }

  condition:
    any of them
}