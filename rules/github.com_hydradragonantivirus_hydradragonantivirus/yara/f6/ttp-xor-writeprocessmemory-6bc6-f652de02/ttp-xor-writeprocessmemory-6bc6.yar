rule TTP_XOR_WriteProcessMemory_6bc6 {
  strings:
    $key_6bc6 = { 3c b4 [2] 0e 96 [2] 08 a3 [2] 26 a3 [2] 19 bf }

  condition:
    any of them
}