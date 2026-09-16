rule TTP_XOR_WriteProcessMemory_fe44 {
  strings:
    $key_fe44 = { a9 36 [2] 9b 14 [2] 9d 21 [2] b3 21 [2] 8c 3d }

  condition:
    any of them
}