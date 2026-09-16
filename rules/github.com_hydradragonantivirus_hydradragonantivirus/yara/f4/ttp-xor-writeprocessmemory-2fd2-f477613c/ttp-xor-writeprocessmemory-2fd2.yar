rule TTP_XOR_WriteProcessMemory_2fd2 {
  strings:
    $key_2fd2 = { 78 a0 [2] 4a 82 [2] 4c b7 [2] 62 b7 [2] 5d ab }

  condition:
    any of them
}