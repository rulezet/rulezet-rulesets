rule TTP_XOR_WriteProcessMemory_f1cd {
  strings:
    $key_f1cd = { a6 bf [2] 94 9d [2] 92 a8 [2] bc a8 [2] 83 b4 }

  condition:
    any of them
}