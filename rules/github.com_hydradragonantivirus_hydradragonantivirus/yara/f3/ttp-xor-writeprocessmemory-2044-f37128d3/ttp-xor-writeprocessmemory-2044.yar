rule TTP_XOR_WriteProcessMemory_2044 {
  strings:
    $key_2044 = { 77 36 [2] 45 14 [2] 43 21 [2] 6d 21 [2] 52 3d }

  condition:
    any of them
}