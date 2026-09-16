rule TTP_XOR_WriteProcessMemory_2afa {
  strings:
    $key_2afa = { 7d 88 [2] 4f aa [2] 49 9f [2] 67 9f [2] 58 83 }

  condition:
    any of them
}