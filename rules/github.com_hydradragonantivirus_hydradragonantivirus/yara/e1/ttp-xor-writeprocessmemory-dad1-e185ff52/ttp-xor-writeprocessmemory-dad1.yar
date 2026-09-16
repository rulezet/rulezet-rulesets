rule TTP_XOR_WriteProcessMemory_dad1 {
  strings:
    $key_dad1 = { 8d a3 [2] bf 81 [2] b9 b4 [2] 97 b4 [2] a8 a8 }

  condition:
    any of them
}