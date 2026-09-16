rule TTP_XOR_WriteProcessMemory_70d8 {
  strings:
    $key_70d8 = { 27 aa [2] 15 88 [2] 13 bd [2] 3d bd [2] 02 a1 }

  condition:
    any of them
}