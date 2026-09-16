rule TTP_XOR_WriteProcessMemory_2ecd {
  strings:
    $key_2ecd = { 79 bf [2] 4b 9d [2] 4d a8 [2] 63 a8 [2] 5c b4 }

  condition:
    any of them
}