rule TTP_XOR_WriteProcessMemory_0da2 {
  strings:
    $key_0da2 = { 5a d0 [2] 68 f2 [2] 6e c7 [2] 40 c7 [2] 7f db }

  condition:
    any of them
}