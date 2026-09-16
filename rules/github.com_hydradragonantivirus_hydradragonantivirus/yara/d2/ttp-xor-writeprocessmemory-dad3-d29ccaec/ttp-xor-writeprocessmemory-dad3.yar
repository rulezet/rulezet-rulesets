rule TTP_XOR_WriteProcessMemory_dad3 {
  strings:
    $key_dad3 = { 8d a1 [2] bf 83 [2] b9 b6 [2] 97 b6 [2] a8 aa }

  condition:
    any of them
}