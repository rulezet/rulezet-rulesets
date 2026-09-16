rule TTP_XOR_WriteProcessMemory_16cd {
  strings:
    $key_16cd = { 41 bf [2] 73 9d [2] 75 a8 [2] 5b a8 [2] 64 b4 }

  condition:
    any of them
}