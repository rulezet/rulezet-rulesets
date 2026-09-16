rule TTP_XOR_WriteProcessMemory_b9df {
  strings:
    $key_b9df = { ee ad [2] dc 8f [2] da ba [2] f4 ba [2] cb a6 }

  condition:
    any of them
}