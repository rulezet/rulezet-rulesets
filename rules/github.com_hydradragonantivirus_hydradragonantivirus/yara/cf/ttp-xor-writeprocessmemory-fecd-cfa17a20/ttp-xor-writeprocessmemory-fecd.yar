rule TTP_XOR_WriteProcessMemory_fecd {
  strings:
    $key_fecd = { a9 bf [2] 9b 9d [2] 9d a8 [2] b3 a8 [2] 8c b4 }

  condition:
    any of them
}