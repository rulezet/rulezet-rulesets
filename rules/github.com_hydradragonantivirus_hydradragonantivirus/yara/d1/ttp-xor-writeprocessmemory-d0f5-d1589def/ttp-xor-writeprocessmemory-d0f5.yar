rule TTP_XOR_WriteProcessMemory_d0f5 {
  strings:
    $key_d0f5 = { 87 87 [2] b5 a5 [2] b3 90 [2] 9d 90 [2] a2 8c }

  condition:
    any of them
}