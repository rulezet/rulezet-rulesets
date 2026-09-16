rule TTP_XOR_WriteProcessMemory_9ac6 {
  strings:
    $key_9ac6 = { cd b4 [2] ff 96 [2] f9 a3 [2] d7 a3 [2] e8 bf }

  condition:
    any of them
}