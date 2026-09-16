rule TTP_XOR_WriteProcessMemory_28d8 {
  strings:
    $key_28d8 = { 7f aa [2] 4d 88 [2] 4b bd [2] 65 bd [2] 5a a1 }

  condition:
    any of them
}