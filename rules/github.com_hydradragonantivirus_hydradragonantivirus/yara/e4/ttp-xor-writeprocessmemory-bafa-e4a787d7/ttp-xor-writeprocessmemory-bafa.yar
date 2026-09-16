rule TTP_XOR_WriteProcessMemory_bafa {
  strings:
    $key_bafa = { ed 88 [2] df aa [2] d9 9f [2] f7 9f [2] c8 83 }

  condition:
    any of them
}