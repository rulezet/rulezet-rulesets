rule TTP_XOR_WriteProcessMemory_2d93 {
  strings:
    $key_2d93 = { 7a e1 [2] 48 c3 [2] 4e f6 [2] 60 f6 [2] 5f ea }

  condition:
    any of them
}