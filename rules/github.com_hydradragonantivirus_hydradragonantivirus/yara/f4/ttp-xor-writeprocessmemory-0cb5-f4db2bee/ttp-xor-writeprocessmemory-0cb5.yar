rule TTP_XOR_WriteProcessMemory_0cb5 {
  strings:
    $key_0cb5 = { 5b c7 [2] 69 e5 [2] 6f d0 [2] 41 d0 [2] 7e cc }

  condition:
    any of them
}