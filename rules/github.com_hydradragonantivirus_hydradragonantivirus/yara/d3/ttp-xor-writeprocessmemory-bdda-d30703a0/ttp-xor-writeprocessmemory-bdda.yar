rule TTP_XOR_WriteProcessMemory_bdda {
  strings:
    $key_bdda = { ea a8 [2] d8 8a [2] de bf [2] f0 bf [2] cf a3 }

  condition:
    any of them
}