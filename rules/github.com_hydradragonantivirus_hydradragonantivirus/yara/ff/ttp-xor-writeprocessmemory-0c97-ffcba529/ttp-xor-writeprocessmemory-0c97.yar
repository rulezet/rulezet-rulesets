rule TTP_XOR_WriteProcessMemory_0c97 {
  strings:
    $key_0c97 = { 5b e5 [2] 69 c7 [2] 6f f2 [2] 41 f2 [2] 7e ee }

  condition:
    any of them
}