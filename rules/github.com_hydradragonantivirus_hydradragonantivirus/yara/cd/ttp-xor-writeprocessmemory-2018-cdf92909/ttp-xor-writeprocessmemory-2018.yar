rule TTP_XOR_WriteProcessMemory_2018 {
  strings:
    $key_2018 = { 77 6a [2] 45 48 [2] 43 7d [2] 6d 7d [2] 52 61 }

  condition:
    any of them
}