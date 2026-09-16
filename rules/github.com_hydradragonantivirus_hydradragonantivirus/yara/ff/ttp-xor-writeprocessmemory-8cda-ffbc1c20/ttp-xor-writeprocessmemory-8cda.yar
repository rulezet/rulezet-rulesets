rule TTP_XOR_WriteProcessMemory_8cda {
  strings:
    $key_8cda = { db a8 [2] e9 8a [2] ef bf [2] c1 bf [2] fe a3 }

  condition:
    any of them
}