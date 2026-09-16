rule TTP_XOR_WriteProcessMemory_0ada {
  strings:
    $key_0ada = { 5d a8 [2] 6f 8a [2] 69 bf [2] 47 bf [2] 78 a3 }

  condition:
    any of them
}