rule TTP_XOR_WriteProcessMemory_7fdd {
  strings:
    $key_7fdd = { 28 af [2] 1a 8d [2] 1c b8 [2] 32 b8 [2] 0d a4 }

  condition:
    any of them
}