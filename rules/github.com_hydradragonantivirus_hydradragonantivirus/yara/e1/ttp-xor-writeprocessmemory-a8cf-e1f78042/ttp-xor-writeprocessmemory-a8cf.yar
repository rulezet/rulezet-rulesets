rule TTP_XOR_WriteProcessMemory_a8cf {
  strings:
    $key_a8cf = { ff bd [2] cd 9f [2] cb aa [2] e5 aa [2] da b6 }

  condition:
    any of them
}