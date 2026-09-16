rule TTP_XOR_WriteProcessMemory_ee43 {
  strings:
    $key_ee43 = { b9 31 [2] 8b 13 [2] 8d 26 [2] a3 26 [2] 9c 3a }

  condition:
    any of them
}