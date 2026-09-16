rule TTP_XOR_WriteProcessMemory_2bc6 {
  strings:
    $key_2bc6 = { 7c b4 [2] 4e 96 [2] 48 a3 [2] 66 a3 [2] 59 bf }

  condition:
    any of them
}