rule TTP_XOR_WriteProcessMemory_3fd2 {
  strings:
    $key_3fd2 = { 68 a0 [2] 5a 82 [2] 5c b7 [2] 72 b7 [2] 4d ab }

  condition:
    any of them
}