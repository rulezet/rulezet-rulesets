rule TTP_XOR_WriteProcessMemory_0c94 {
  strings:
    $key_0c94 = { 5b e6 [2] 69 c4 [2] 6f f1 [2] 41 f1 [2] 7e ed }

  condition:
    any of them
}