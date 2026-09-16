rule TTP_XOR_WriteProcessMemory_7c96 {
  strings:
    $key_7c96 = { 2b e4 [2] 19 c6 [2] 1f f3 [2] 31 f3 [2] 0e ef }

  condition:
    any of them
}