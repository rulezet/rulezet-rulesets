rule TTP_XOR_WriteProcessMemory_effa {
  strings:
    $key_effa = { b8 88 [2] 8a aa [2] 8c 9f [2] a2 9f [2] 9d 83 }

  condition:
    any of them
}