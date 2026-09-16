rule TTP_XOR_WriteProcessMemory_1bc6 {
  strings:
    $key_1bc6 = { 4c b4 [2] 7e 96 [2] 78 a3 [2] 56 a3 [2] 69 bf }

  condition:
    any of them
}