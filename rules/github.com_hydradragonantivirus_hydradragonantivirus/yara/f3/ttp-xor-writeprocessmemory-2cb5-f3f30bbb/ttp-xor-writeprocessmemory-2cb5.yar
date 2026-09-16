rule TTP_XOR_WriteProcessMemory_2cb5 {
  strings:
    $key_2cb5 = { 7b c7 [2] 49 e5 [2] 4f d0 [2] 61 d0 [2] 5e cc }

  condition:
    any of them
}