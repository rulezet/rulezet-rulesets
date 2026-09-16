rule TTP_XOR_WriteProcessMemory_ddda {
  strings:
    $key_ddda = { 8a a8 [2] b8 8a [2] be bf [2] 90 bf [2] af a3 }

  condition:
    any of them
}