rule TTP_XOR_WriteProcessMemory_1ed8 {
  strings:
    $key_1ed8 = { 49 aa [2] 7b 88 [2] 7d bd [2] 53 bd [2] 6c a1 }

  condition:
    any of them
}