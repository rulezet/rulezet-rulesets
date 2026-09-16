rule TTP_XOR_WriteProcessMemory_0c96 {
  strings:
    $key_0c96 = { 5b e4 [2] 69 c6 [2] 6f f3 [2] 41 f3 [2] 7e ef }

  condition:
    any of them
}