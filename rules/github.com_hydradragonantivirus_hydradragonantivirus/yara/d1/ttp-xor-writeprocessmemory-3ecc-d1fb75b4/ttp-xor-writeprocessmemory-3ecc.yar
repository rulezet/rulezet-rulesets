rule TTP_XOR_WriteProcessMemory_3ecc {
  strings:
    $key_3ecc = { 69 be [2] 5b 9c [2] 5d a9 [2] 73 a9 [2] 4c b5 }

  condition:
    any of them
}