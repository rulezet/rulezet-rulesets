rule TTP_XOR_WriteProcessMemory_1ecd {
  strings:
    $key_1ecd = { 49 bf [2] 7b 9d [2] 7d a8 [2] 53 a8 [2] 6c b4 }

  condition:
    any of them
}