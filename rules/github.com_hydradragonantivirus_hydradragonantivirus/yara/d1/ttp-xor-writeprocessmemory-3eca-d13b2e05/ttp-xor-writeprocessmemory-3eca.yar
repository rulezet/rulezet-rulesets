rule TTP_XOR_WriteProcessMemory_3eca {
  strings:
    $key_3eca = { 69 b8 [2] 5b 9a [2] 5d af [2] 73 af [2] 4c b3 }

  condition:
    any of them
}