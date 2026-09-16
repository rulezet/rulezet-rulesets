rule TTP_XOR_WriteProcessMemory_3fda {
  strings:
    $key_3fda = { 68 a8 [2] 5a 8a [2] 5c bf [2] 72 bf [2] 4d a3 }

  condition:
    any of them
}