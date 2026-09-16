rule TTP_XOR_WriteProcessMemory_fbd8 {
  strings:
    $key_fbd8 = { ac aa [2] 9e 88 [2] 98 bd [2] b6 bd [2] 89 a1 }

  condition:
    any of them
}