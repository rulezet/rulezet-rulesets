rule TTP_XOR_WriteProcessMemory_e0d8 {
  strings:
    $key_e0d8 = { b7 aa [2] 85 88 [2] 83 bd [2] ad bd [2] 92 a1 }

  condition:
    any of them
}