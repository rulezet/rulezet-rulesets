rule TTP_XOR_WriteProcessMemory_4bc4 {
  strings:
    $key_4bc4 = { 1c b6 [2] 2e 94 [2] 28 a1 [2] 06 a1 [2] 39 bd }

  condition:
    any of them
}