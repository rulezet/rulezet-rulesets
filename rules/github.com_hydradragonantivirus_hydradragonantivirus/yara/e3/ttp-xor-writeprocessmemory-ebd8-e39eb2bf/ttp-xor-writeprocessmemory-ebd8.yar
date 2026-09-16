rule TTP_XOR_WriteProcessMemory_ebd8 {
  strings:
    $key_ebd8 = { bc aa [2] 8e 88 [2] 88 bd [2] a6 bd [2] 99 a1 }

  condition:
    any of them
}