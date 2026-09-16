rule TTP_XOR_WriteProcessMemory_4ef5 {
  strings:
    $key_4ef5 = { 19 87 [2] 2b a5 [2] 2d 90 [2] 03 90 [2] 3c 8c }

  condition:
    any of them
}