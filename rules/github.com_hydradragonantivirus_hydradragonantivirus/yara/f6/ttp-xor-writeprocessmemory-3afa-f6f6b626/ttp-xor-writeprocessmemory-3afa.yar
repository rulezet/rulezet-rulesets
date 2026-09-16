rule TTP_XOR_WriteProcessMemory_3afa {
  strings:
    $key_3afa = { 6d 88 [2] 5f aa [2] 59 9f [2] 77 9f [2] 48 83 }

  condition:
    any of them
}