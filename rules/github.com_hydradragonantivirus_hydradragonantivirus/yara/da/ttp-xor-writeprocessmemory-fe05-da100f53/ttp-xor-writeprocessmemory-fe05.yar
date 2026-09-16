rule TTP_XOR_WriteProcessMemory_fe05 {
  strings:
    $key_fe05 = { a9 77 [2] 9b 55 [2] 9d 60 [2] b3 60 [2] 8c 7c }

  condition:
    any of them
}